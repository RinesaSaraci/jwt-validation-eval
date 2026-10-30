"""Regression tests for the validation configurations (stdlib unittest).

Run:  python -m unittest discover -s tests -v
"""
import unittest
import warnings

from app.keys import make_keyring
from app.policies import POLICIES, TokenRejected
from experiments.scenarios import build_all

warnings.filterwarnings("ignore")


def decide(pid, tok, kr):
    try:
        POLICIES[pid](tok, kr)
        return "accept"
    except TokenRejected:
        return "reject"


class HardenedPolicy(unittest.TestCase):
    """C5 must accept every valid token and reject every invalid one."""

    def _check(self, mode):
        kr = make_keyring(mode)
        for sc, tok in build_all(kr):
            if tok is None:
                continue
            with self.subTest(mode=mode, scenario=sc.sid):
                exp = "accept" if sc.should_accept else "reject"
                self.assertEqual(decide("C5", tok, kr), exp)

    def test_rs256(self):
        self._check("RS256")

    def test_hs256(self):
        self._check("HS256")


class KnownWeaknesses(unittest.TestCase):
    """Documents the weaknesses observed for the weaker configurations."""

    @classmethod
    def setUpClass(cls):
        cls.kr = make_keyring("RS256")
        cls.tok = {sc.sid: t for sc, t in build_all(cls.kr)}

    def test_unverified_accepts_forgery(self):
        self.assertEqual(decide("C0", self.tok["A1"], self.kr), "accept")

    def test_header_alg_accepts_non_allowlisted_alg(self):
        self.assertEqual(decide("C1", self.tok["A4"], self.kr), "accept")

    def test_header_alg_still_blocks_none_and_confusion(self):
        # PyJWT refuses a non-empty key for alg=none and PEM keys as HMAC secrets
        self.assertEqual(decide("C1", self.tok["A1"], self.kr), "reject")
        self.assertEqual(decide("C1", self.tok["A3"], self.kr), "reject")

    def test_default_rejects_valid_token_with_aud(self):
        self.assertEqual(decide("C2", self.tok["V1"], self.kr), "reject")

    def test_default_accepts_missing_aud(self):
        self.assertEqual(decide("C2", self.tok["U2"], self.kr), "accept")

    def test_default_no_aud_accepts_foreign_issuer(self):
        self.assertEqual(decide("C3", self.tok["I1"], self.kr), "accept")

    def test_explicit_misses_type_and_lifetime(self):
        self.assertEqual(decide("C4", self.tok["X1"], self.kr), "accept")
        self.assertEqual(decide("C4", self.tok["T6"], self.kr), "accept")


if __name__ == "__main__":
    unittest.main()
