"""End-to-end checks through the FastAPI layer.

Requires: fastapi, httpx  (pip install -r requirements.txt)
Run:      python -m unittest tests.test_api -v
"""
import unittest
import warnings

warnings.filterwarnings("ignore")

try:
    from fastapi.testclient import TestClient
    from app import main
    HAVE_FASTAPI = True
except ImportError:          # pragma: no cover
    HAVE_FASTAPI = False


@unittest.skipUnless(HAVE_FASTAPI, "fastapi/httpx not installed")
class ApiDecisions(unittest.TestCase):
    """HTTP decisions must equal the validator-level decisions."""

    @classmethod
    def setUpClass(cls):
        from experiments.scenarios import build_all
        from app.policies import POLICIES, TokenRejected
        cls.client = TestClient(main.app)
        cls.tokens = [(sc, t) for sc, t in build_all(main.KEYRING) if t is not None]
        cls.POLICIES, cls.TokenRejected = POLICIES, TokenRejected

    def test_login_and_access(self):
        r = self.client.post("/auth/token",
                             json={"username": "alice", "password": "alice-pass"})
        self.assertEqual(r.status_code, 200)
        tok = r.json()["access_token"]
        r = self.client.get("/api/C5/profile",
                            headers={"Authorization": f"Bearer {tok}"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["sub"], "user-1042")

    def test_http_matches_validator(self):
        for pid, fn in self.POLICIES.items():
            for sc, tok in self.tokens:
                try:
                    fn(tok, main.KEYRING)
                    expected = 200
                except self.TokenRejected:
                    expected = 401
                with self.subTest(policy=pid, scenario=sc.sid):
                    r = self.client.get(f"/api/{pid}/profile",
                                        headers={"Authorization": f"Bearer {tok}"})
                    self.assertEqual(r.status_code, expected)

    def test_missing_header(self):
        r = self.client.get("/api/C5/profile")
        self.assertIn(r.status_code, (401, 403))


if __name__ == "__main__":
    unittest.main()
