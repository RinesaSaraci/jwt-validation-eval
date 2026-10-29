
from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

ISSUER = "https://auth.lab.local"
AUDIENCE = "orders-api"
TOKEN_TYPE = "at+jwt"
MAX_LIFETIME_S = 3600


def _rsa_pair(bits: int = 2048):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


@dataclass
class KeyRing:
    """Keys known to the server (legitimate) and to the attacker."""

    mode: str
    
    rsa_private: bytes = field(default=b"", repr=False)
    rsa_public: bytes = field(default=b"", repr=False)
    hmac_secret: bytes = field(default=b"", repr=False)

    attacker_rsa_private: bytes = field(default=b"", repr=False)
    attacker_hmac_secret: bytes = field(default=b"", repr=False)
    attacker_ec_private: object = field(default=None, repr=False)

    @property
    def alg(self) -> str:
        return self.mode

    @property
    def signing_key(self):
        return self.rsa_private if self.mode == "RS256" else self.hmac_secret

    @property
    def verification_key(self):
        return self.rsa_public if self.mode == "RS256" else self.hmac_secret


def make_keyring(mode: str = "RS256") -> KeyRing:
    if mode not in ("RS256", "HS256"):
        raise ValueError("mode must be RS256 or HS256")
    kr = KeyRing(mode=mode)
    kr.rsa_private, kr.rsa_public = _rsa_pair()
    kr.hmac_secret = secrets.token_bytes(32)
    kr.attacker_rsa_private, _ = _rsa_pair()
    kr.attacker_hmac_secret = secrets.token_bytes(32)
    kr.attacker_ec_private = ec.generate_private_key(ec.SECP256R1())
    return kr
