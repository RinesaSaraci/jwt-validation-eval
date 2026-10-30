"""FastAPI authentication prototype.

Endpoints
  POST /auth/token                 issue an access token for a demo user
  GET  /api/{policy}/profile       protected resource, validated with policy C0..C5
  GET  /policies                   list the validation configurations

The keys are generated in memory at start-up (see app/keys.py). Run with:
    JWT_MODE=RS256 uvicorn app.main:app --reload
"""
from __future__ import annotations

import os
import time

import jwt
from fastapi import Depends, FastAPI, HTTPException, Path
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from .keys import AUDIENCE, ISSUER, TOKEN_TYPE, make_keyring
from .policies import POLICIES, POLICY_LABELS, TokenRejected

MODE = os.environ.get("JWT_MODE", "RS256")
KEYRING = make_keyring(MODE)

# Demo user store -- never store plaintext passwords in a real system.
USERS = {"alice": {"password": "alice-pass", "sub": "user-1042", "role": "user"}}

app = FastAPI(title="JWT validation testbed", version="1.0")
bearer = HTTPBearer(auto_error=True)


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/auth/token")
def issue_token(body: LoginRequest):
    user = USERS.get(body.username)
    if user is None or user["password"] != body.password:
        raise HTTPException(status_code=401, detail="invalid credentials")
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": user["sub"],
              "role": user["role"], "iat": now, "nbf": now, "exp": now + 900}
    token = jwt.encode(claims, KEYRING.signing_key, algorithm=KEYRING.alg,
                       headers={"typ": TOKEN_TYPE})
    return {"access_token": token, "token_type": "Bearer", "expires_in": 900}


@app.get("/policies")
def list_policies():
    return {"mode": MODE, "policies": POLICY_LABELS}


def authenticate(policy: str = Path(..., pattern="^C[0-5]$"),
                 cred: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    validator = POLICIES[policy]
    try:
        return validator(cred.credentials, KEYRING)
    except TokenRejected as e:
        raise HTTPException(status_code=401, detail=f"token rejected: {e.reason}",
                            headers={"WWW-Authenticate": "Bearer"})


@app.get("/api/{policy}/profile")
def profile(policy: str, claims: dict = Depends(authenticate)):
    return {"policy": policy, "sub": claims.get("sub"), "role": claims.get("role")}
