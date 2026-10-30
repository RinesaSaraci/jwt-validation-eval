"""Synthetic test tokens: two valid tokens and a set of invalid/manipulated ones.

Each scenario carries a category, a short description and the ground-truth
decision (``should_accept``) that a correctly configured relying party must
make under the declared security policy of the testbed:
  * tokens are RS256 (or HS256) access tokens issued by ISSUER for AUDIENCE,
  * header typ = "at+jwt" (RFC 9068), lifetime <= 1 h,
  * exp, iat, iss, aud and sub are mandatory.
"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Callable, List, Optional

import jwt
from cryptography.hazmat.primitives import serialization

from app.keys import AUDIENCE, ISSUER, TOKEN_TYPE, KeyRing


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_json(obj) -> str:
    return b64u(json.dumps(obj, separators=(",", ":")).encode())


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@dataclass
class Scenario:
    sid: str
    category: str
    description: str
    should_accept: bool
    build: Callable[[KeyRing, int], Optional[str]]  # None = not applicable


def base_claims(now: int, **overrides) -> dict:
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-1042",
        "role": "user",
        "iat": now,
        "nbf": now,
        "exp": now + 900,          # 15 min
        "jti": "tkn-0001",
    }
    for k, v in overrides.items():
        if v is _DROP:
            claims.pop(k, None)
        else:
            claims[k] = v
    return claims


_DROP = object()


def sign(kr: KeyRing, claims: dict, alg: Optional[str] = None, key=None,
         typ: Optional[str] = TOKEN_TYPE, extra_headers=None) -> str:
    headers = {"typ": typ} if typ else {}
    if extra_headers:
        headers.update(extra_headers)
    return jwt.encode(claims, key if key is not None else kr.signing_key,
                      algorithm=alg or kr.alg, headers=headers)


def unsigned(header: dict, claims: dict) -> str:
    return f"{b64u_json(header)}.{b64u_json(claims)}."


# --------------------------------------------------------------- builders
def _valid(kr, now):
    return sign(kr, base_claims(now))


def _valid_aud_list(kr, now):
    return sign(kr, base_claims(now, aud=["billing-api", AUDIENCE]))


def _tampered_payload(kr, now):
    h, _, s = _valid(kr, now).split(".")
    forged = b64u_json(base_claims(now, sub="admin", role="admin"))
    return f"{h}.{forged}.{s}"


def _flipped_signature(kr, now):
    h, p, s = _valid(kr, now).split(".")
    raw = bytearray(b64u_decode(s))
    raw[len(raw) // 2] ^= 0x01
    return f"{h}.{p}.{b64u(bytes(raw))}"


def _stripped_signature(kr, now):
    h, p, _ = _valid(kr, now).split(".")
    return f"{h}.{p}."


def _attacker_key(kr, now):
    key = kr.attacker_rsa_private if kr.mode == "RS256" else kr.attacker_hmac_secret
    return sign(kr, base_claims(now, role="admin"), key=key)


def _alg_none(kr, now):
    return unsigned({"alg": "none", "typ": TOKEN_TYPE}, base_claims(now, role="admin"))


def _alg_none_case(kr, now):
    return unsigned({"alg": "nOnE", "typ": TOKEN_TYPE}, base_claims(now, role="admin"))


def _alg_confusion(kr, now):
    """HS256 token whose HMAC key is the server's RSA public key (PEM)."""
    if kr.mode != "RS256":
        return None
    import hmac
    import hashlib
    header = b64u_json({"alg": "HS256", "typ": TOKEN_TYPE})
    payload = b64u_json(base_claims(now, role="admin"))
    signing_input = f"{header}.{payload}".encode()
    mac = hmac.new(kr.rsa_public, signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{b64u(mac)}"


def _non_allowlisted_alg(kr, now):
    """Genuinely signed with the server key but with a non-allow-listed alg."""
    alg = "RS512" if kr.mode == "RS256" else "HS512"
    return sign(kr, base_claims(now), alg=alg)


def _embedded_jwk(kr, now):
    """ES256 token signed by the attacker, attacker public key in 'jwk' header."""
    pub = kr.attacker_ec_private.public_key()
    jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(pub))
    pem = kr.attacker_ec_private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return sign(kr, base_claims(now, role="admin"), alg="ES256", key=pem,
                extra_headers={"jwk": jwk})


def _wrong_iss(kr, now):
    return sign(kr, base_claims(now, iss="https://evil.example"))


def _missing_iss(kr, now):
    return sign(kr, base_claims(now, iss=_DROP))


def _wrong_aud(kr, now):
    return sign(kr, base_claims(now, aud="billing-api"))


def _missing_aud(kr, now):
    return sign(kr, base_claims(now, aud=_DROP))


def _aud_list_foreign(kr, now):
    return sign(kr, base_claims(now, aud=["billing-api", "reports-api"]))


def _expired(kr, now):
    return sign(kr, base_claims(now - 7200, exp=now - 3600))


def _missing_exp(kr, now):
    return sign(kr, base_claims(now, exp=_DROP))


def _nbf_future(kr, now):
    return sign(kr, base_claims(now, nbf=now + 3600, exp=now + 4000))


def _iat_future(kr, now):
    return sign(kr, base_claims(now, iat=now + 3600, nbf=_DROP, exp=now + 4000))


def _exp_string(kr, now):
    return sign(kr, base_claims(now, exp="never"))


def _long_lifetime(kr, now):
    return sign(kr, base_claims(now, exp=now + 365 * 24 * 3600))


def _wrong_typ(kr, now):
    """Token of another type (e.g. an ID token) presented as access token."""
    return sign(kr, base_claims(now), typ="JWT")


def _missing_sub(kr, now):
    return sign(kr, base_claims(now, sub=_DROP))


def _two_segments(kr, now):
    h, p, _ = _valid(kr, now).split(".")
    return f"{h}.{p}"


def _garbage(kr, now):
    return "not-a.jwt.!!!"


SCENARIOS: List[Scenario] = [
    Scenario("V1", "Valid", "Well-formed token, all claims correct", True, _valid),
    Scenario("V2", "Valid", "aud is an array containing our audience", True, _valid_aud_list),
    Scenario("S1", "Signature", "Payload modified (role=admin), original signature", False, _tampered_payload),
    Scenario("S2", "Signature", "One bit of the signature flipped", False, _flipped_signature),
    Scenario("S3", "Signature", "Signature removed (empty third segment)", False, _stripped_signature),
    Scenario("S4", "Signature", "Signed with an attacker-controlled key", False, _attacker_key),
    Scenario("A1", "Algorithm", "alg=none, no signature", False, _alg_none),
    Scenario("A2", "Algorithm", "alg=nOnE (case variant), no signature", False, _alg_none_case),
    Scenario("A3", "Algorithm", "RS256->HS256 confusion, public key as HMAC secret", False, _alg_confusion),
    Scenario("A4", "Algorithm", "Valid signature, non-allow-listed algorithm", False, _non_allowlisted_alg),
    Scenario("A5", "Algorithm", "ES256 + attacker key embedded in jwk header", False, _embedded_jwk),
    Scenario("I1", "Issuer", "Wrong issuer", False, _wrong_iss),
    Scenario("I2", "Issuer", "Missing iss claim", False, _missing_iss),
    Scenario("U1", "Audience", "Wrong audience (string)", False, _wrong_aud),
    Scenario("U2", "Audience", "Missing aud claim", False, _missing_aud),
    Scenario("U3", "Audience", "aud array without our audience", False, _aud_list_foreign),
    Scenario("T1", "Time", "Expired one hour ago", False, _expired),
    Scenario("T2", "Time", "Missing exp claim", False, _missing_exp),
    Scenario("T3", "Time", "nbf one hour in the future", False, _nbf_future),
    Scenario("T4", "Time", "iat one hour in the future", False, _iat_future),
    Scenario("T5", "Time", "exp is a non-numeric string", False, _exp_string),
    Scenario("T6", "Time", "Lifetime of one year (policy max 1 h)", False, _long_lifetime),
    Scenario("X1", "Structure", "typ=JWT instead of at+jwt (token-type confusion)", False, _wrong_typ),
    Scenario("X2", "Structure", "Missing sub claim", False, _missing_sub),
    Scenario("X3", "Structure", "Only two segments", False, _two_segments),
    Scenario("X4", "Structure", "Non-base64 garbage", False, _garbage),
]


def build_all(kr: KeyRing, now: Optional[int] = None):
    now = int(time.time()) if now is None else now
    out = []
    for sc in SCENARIOS:
        tok = sc.build(kr, now)
        out.append((sc, tok))
    return out
