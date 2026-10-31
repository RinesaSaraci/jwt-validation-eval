"""Measure the validation time of every configuration.

Two workloads per key mode and configuration:
  * valid   - the valid token V1, repeated N_VALID times per repetition
  * mixed   - all applicable scenario tokens, cycled N_MIXED times
Each workload is repeated REPS times after a warm-up; we report the mean
and standard deviation (across repetitions) of the per-token time in us.

Usage:  python -m experiments.benchmark [--quick]
"""
from __future__ import annotations

import json
import statistics
import sys
import time
import warnings
from pathlib import Path

from app.keys import make_keyring
from app.policies import POLICIES, TokenRejected
from experiments.run_matrix import environment
from experiments.scenarios import build_all

warnings.filterwarnings("ignore")
RESULTS = Path(__file__).resolve().parent.parent / "results"

QUICK = "--quick" in sys.argv
REPS = 3 if QUICK else 10
N_VALID = 500 if QUICK else 5000
N_MIXED = 50 if QUICK else 400
WARMUP = 200


def _time_loop(fn, tokens, kr, loops):
    t0 = time.perf_counter_ns()
    for _ in range(loops):
        for tok in tokens:
            try:
                fn(tok, kr)
            except TokenRejected:
                pass
    return (time.perf_counter_ns() - t0) / (loops * len(tokens)) / 1000.0


def _c4_preparsed_factory(kr):
    """C4 with the verification key parsed once (RS256 only)."""
    import jwt
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from app.keys import AUDIENCE, ISSUER
    from app.policies import EXPLICIT_OPTIONS
    key = load_pem_public_key(kr.rsa_public)

    def fn(token, _kr):
        try:
            return jwt.decode(token, key, algorithms=["RS256"], issuer=ISSUER,
                              audience=AUDIENCE, options=EXPLICIT_OPTIONS,
                              leeway=30)
        except (jwt.PyJWTError, ValueError, TypeError, KeyError) as e:
            raise TokenRejected(type(e).__name__) from e
    return fn


def bench(mode):
    kr = make_keyring(mode)
    built = [(sc, t) for sc, t in build_all(kr) if t is not None]
    valid = [t for sc, t in built if sc.sid == "V1"]
    mixed = [t for _, t in built]
    out = {}
    policies = dict(POLICIES)
    if mode == "RS256":
        policies["C4k"] = _c4_preparsed_factory(kr)
    for pid, fn in policies.items():
        _time_loop(fn, mixed, kr, max(1, WARMUP // len(mixed)))
        v = [_time_loop(fn, valid, kr, N_VALID) for _ in range(REPS)]
        m = [_time_loop(fn, mixed, kr, N_MIXED) for _ in range(REPS)]
        out[pid] = {
            "valid_mean_us": statistics.mean(v), "valid_sd_us": statistics.stdev(v),
            "mixed_mean_us": statistics.mean(m), "mixed_sd_us": statistics.stdev(m),
        }
        print(f"{mode} {pid}: valid {out[pid]['valid_mean_us']:.2f}"
              f"±{out[pid]['valid_sd_us']:.2f} us   mixed "
              f"{out[pid]['mixed_mean_us']:.2f}±{out[pid]['mixed_sd_us']:.2f} us",
              flush=True)
    return out


def main():
    RESULTS.mkdir(exist_ok=True)
    res = {"environment": environment(),
           "params": {"reps": REPS, "n_valid": N_VALID, "n_mixed": N_MIXED},
           "modes": {m: bench(m) for m in ("RS256", "HS256")}}
    # a quick run never overwrites the full results used in the paper
    name = "timing_quick.json" if QUICK else "timing.json"
    (RESULTS / name).write_text(json.dumps(res, indent=2))
    print("written to", RESULTS / name)


if __name__ == "__main__":
    main()
