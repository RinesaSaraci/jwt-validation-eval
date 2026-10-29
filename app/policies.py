from __future__ import annotations

from typing import Callable, Dict

import jwt

from .keys import AUDIENCE, ISSUER, MAX_LIFETIME_S, TOKEN_TYPE, KeyRing


class TokenRejected(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _wrap(fn):
    def inner(token: str, kr: KeyRing):
        try:
            return fn(token, kr)
        except TokenRejected:
            raise
        except jwt.PyJWTError as e:
            raise TokenRejected(type(e).__name__) from e
        except (ValueError, TypeError, KeyError) as e:
            raise TokenRejected(type(e).__name__) from e
    inner.__name__ = fn.__name__
    inner.__doc__ = fn.__doc__
    return inner


@_wrap
def c0_unverified(token: str, kr: KeyRing) -> dict:
    """Anti-pattern: read claims without verifying anything."""
    return jwt.decode(token, options={"verify_signature": False})


@_wrap
def c1_header_alg(token: str, kr: KeyRing) -> dict:
    """Anti-pattern: let the token choose the verification algorithm."""
    alg = jwt.get_unverified_header(token).get("alg")
    return jwt.decode(token, kr.verification_key, algorithms=[alg],
                      options={"verify_aud": False})


@_wrap
def c2_library_default(token: str, kr: KeyRing) -> dict:
    """Minimal configuration: key + expected algorithm, defaults otherwise."""
    return jwt.decode(token, kr.verification_key, algorithms=[kr.alg])


@_wrap
def c3_default_no_aud(token: str, kr: KeyRing) -> dict:
    """Library default with the audience check disabled (common workaround)."""
    return jwt.decode(token, kr.verification_key, algorithms=[kr.alg],
                      options={"verify_aud": False})


EXPLICIT_OPTIONS = {
    "require": ["exp", "iat", "iss", "aud", "sub"],
    "verify_signature": True,
    "verify_exp": True,
    "verify_nbf": True,
    "verify_iat": True,
    "verify_iss": True,
    "verify_aud": True,
    "strict_aud": False,
}


def _explicit_kwargs(kr: KeyRing) -> dict:
    return dict(algorithms=[kr.alg], issuer=ISSUER, audience=AUDIENCE,
                options=EXPLICIT_OPTIONS, leeway=30)


@_wrap
def c4_explicit(token: str, kr: KeyRing) -> dict:
    return jwt.decode(token, kr.verification_key, **_explicit_kwargs(kr))


@_wrap
def c5_explicit_app(token: str, kr: KeyRing) -> dict:


    full = jwt.decode_complete(token, kr.verification_key, **_explicit_kwargs(kr))
    header, claims = full["header"], full["payload"]
    if str(header.get("typ", "")).lower() != TOKEN_TYPE:
        raise TokenRejected("UnexpectedTokenType")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise TokenRejected("InvalidSubject")
    if claims["exp"] - claims["iat"] > MAX_LIFETIME_S:
        raise TokenRejected("LifetimeTooLong")
    return claims


POLICIES: Dict[str, Callable[[str, KeyRing], dict]] = {
    "C0": c0_unverified,
    "C1": c1_header_alg,
    "C2": c2_library_default,
    "C3": c3_default_no_aud,
    "C4": c4_explicit,
    "C5": c5_explicit_app,
}

POLICY_LABELS = {
    "C0": "Unverified decode",
    "C1": "Header-selected alg.",
    "C2": "Library default",
    "C3": "Default, aud off",
    "C4": "Explicit config.",
    "C5": "Explicit + app policy",
}
