"""Run every scenario against every validation configuration.

Output: results/matrix_<MODE>.csv and results/summary.json
Usage:  python -m experiments.run_matrix [--runs N]  (repeat with fresh keys, check decisions match)
"""
from __future__ import annotations

import csv
import json
import platform
import sys
from pathlib import Path

import warnings

import cryptography
import jwt

from app.keys import make_keyring
from app.policies import POLICIES, TokenRejected
from experiments.scenarios import build_all

warnings.filterwarnings("ignore")
RESULTS = Path(__file__).resolve().parent.parent / "results"


def evaluate(mode: str):
    kr = make_keyring(mode)
    rows = []
    for sc, tok in build_all(kr):
        row = {"sid": sc.sid, "category": sc.category,
               "description": sc.description,
               "expected": "accept" if sc.should_accept else "reject"}
        for pid, fn in POLICIES.items():
            if tok is None:
                row[pid] = "n/a"
                row[pid + "_reason"] = ""
                continue
            try:
                fn(tok, kr)
                row[pid] = "accept"
                row[pid + "_reason"] = ""
            except TokenRejected as e:
                row[pid] = "reject"
                row[pid + "_reason"] = e.reason
        rows.append(row)
    return rows


def summarise(rows):
    summ = {}
    for pid in POLICIES:
        s = dict(valid_accepted=0, valid_rejected=0,
                 invalid_rejected=0, invalid_accepted=0,
                 invalid_accepted_ids=[], valid_rejected_ids=[], n=0)
        for r in rows:
            d = r[pid]
            if d == "n/a":
                continue
            s["n"] += 1
            if r["expected"] == "accept":
                if d == "accept":
                    s["valid_accepted"] += 1
                else:
                    s["valid_rejected"] += 1
                    s["valid_rejected_ids"].append(r["sid"])
            else:
                if d == "reject":
                    s["invalid_rejected"] += 1
                else:
                    s["invalid_accepted"] += 1
                    s["invalid_accepted_ids"].append(r["sid"])
        summ[pid] = s
    return summ


def environment():
    return {
        "python": sys.version.split()[0],
        "pyjwt": jwt.__version__,
        "cryptography": cryptography.__version__,
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
    }


def stability_check(mode: str, runs: int, reference_rows) -> bool:
    """Repeat the evaluation with freshly generated keys and compare decisions."""
    ref = [(r["sid"],) + tuple(r[p] for p in POLICIES) for r in reference_rows]
    for i in range(1, runs):
        rows = evaluate(mode)
        cur = [(r["sid"],) + tuple(r[p] for p in POLICIES) for r in rows]
        if cur != ref:
            print(f"[{mode}] run {i + 1}: decisions DIFFER from run 1")
            return False
    print(f"[{mode}] decisions identical in all {runs} runs (fresh keys each run)")
    return True


def main():
    runs = 1
    if "--runs" in sys.argv:
        runs = int(sys.argv[sys.argv.index("--runs") + 1])
    RESULTS.mkdir(exist_ok=True)
    out = {"environment": environment(), "runs": runs, "modes": {}}
    for mode in ("RS256", "HS256"):
        rows = evaluate(mode)
        if runs > 1:
            out.setdefault("stable", {})[mode] = stability_check(mode, runs, rows)
        with open(RESULTS / f"matrix_{mode}.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        out["modes"][mode] = {"rows": rows, "summary": summarise(rows)}
        print(f"\n=== {mode} ===")
        print(f"{'id':4} {'exp':7} " + " ".join(f"{p:>7}" for p in POLICIES))
        for r in rows:
            print(f"{r['sid']:4} {r['expected']:7} " +
                  " ".join(f"{r[p]:>7}" for p in POLICIES))
        for pid, s in out["modes"][mode]["summary"].items():
            print(pid, {k: v for k, v in s.items()})
    (RESULTS / "summary.json").write_text(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
