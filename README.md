# JWT Signature-Validation Evaluation Testbed

Code package for the seminar project **"Security Evaluation of JWT Signature
Validation in Web Authentication Systems"** (Information Security, Faculty of
Electrical and Computer Engineering, University of Prishtina).

Authors: Lizë Syla, Rinesa Saraçi, Yllka Syla

## What it does

The testbed compares six JWT validation configurations built on PyJWT
against a set of 26 synthetic tokens (2 valid, 24 invalid/manipulated) in two
key modes (RS256 and HS256), and measures validation time.

| ID | Configuration | What the code does |
|----|---------------|--------------------|
| C0 | Unverified decode | `jwt.decode(t, options={"verify_signature": False})` |
| C1 | Header-selected algorithm | `algorithms=[header["alg"]]`, audience check off |
| C2 | Library default | `jwt.decode(t, key, algorithms=["RS256"])` |
| C3 | Default, aud off | C2 + `options={"verify_aud": False}` |
| C4 | Explicit configuration | C2 + `issuer`, `audience`, `require=[exp,iat,iss,aud,sub]`, leeway 30 s |
| C5 | Explicit + application policy | C4 + `typ == "at+jwt"` and lifetime ≤ 1 h |

The token scenarios (`experiments/scenarios.py`) cover signature tampering,
`alg=none`, RS256→HS256 key confusion, non-allow-listed algorithms, embedded
`jwk` keys, wrong/missing `iss` and `aud`, expired / missing / malformed
`exp`, future `nbf`/`iat`, excessive lifetime, token-type confusion, missing
`sub`, and malformed tokens.

## Layout

```
app/keys.py            key generation and testbed constants (issuer, audience, ...)
app/policies.py        the six validation configurations (C0-C5)
app/main.py            FastAPI prototype: /auth/token and /api/{C0..C5}/profile
experiments/scenarios.py  token generator (ground truth per scenario)
experiments/run_matrix.py decision matrix  -> results/matrix_*.csv, summary.json
experiments/benchmark.py  validation timing -> results/timing.json
experiments/make_figures.py figures + LaTeX tables -> results/paper/
tests/                 unittest suites (validator level and HTTP level)
```

## Requirements

Python ≥ 3.10. Install the dependencies (PyJWT and cryptography are pinned to
the versions used in the paper):

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
```

## Running

Everything at once (unit tests, decision matrix, benchmark, figures):

```bash
python run_all.py            # ~3 min
python run_all.py --quick    # ~15 s smoke test (does not overwrite the paper's timing results)
```

Or step by step:

```bash
# 1. decision matrix (prints the table, writes results/);
#    --runs 20 repeats it with fresh keys and checks the decisions are identical
python -m experiments.run_matrix --runs 20

# 2. timing benchmark (~2 min; use --quick for a smoke test)
python -m experiments.benchmark

# 3. figures and LaTeX tables for the paper
python -m experiments.make_figures            # -> results/paper/

# 4. tests
python -m unittest discover -s . -p "test_*.py" -v

```

## How to try the API

The FastAPI prototype issues a demo access token and lets you call a protected
profile endpoint using one of the validation policies, C0 through C5. The
examples below use C5, the strictest policy in this testbed.

### 1. Start the server

Activate the virtual environment created above, then start the server from the
project root. In PowerShell:

```powershell
$env:JWT_MODE = "RS256"
python -m uvicorn app.main:app --reload
```

For macOS or Linux, set the mode and start the server with:

```bash
JWT_MODE=RS256 python -m uvicorn app.main:app --reload
```

Keep this terminal open while trying the API. The server listens at
`http://127.0.0.1:8000`. To use HMAC instead, set `JWT_MODE` to `HS256` before
starting the server.

The prototype has one demo account: `alice` / `alice-pass`. The credentials
and in-memory keys are for local demonstration only; do not use them in a real
deployment.

### 2. Try the API with Swagger UI

With the server running, open
[`http://127.0.0.1:8000/docs`](http://127.0.0.1:8000/docs) in a browser.

1. Expand **POST /auth/token**, select **Try it out**, and use this request
   body:

   ```json
   {
     "username": "alice",
     "password": "alice-pass"
   }
   ```

2. Select **Execute**. In the response body, copy the value of
   `access_token`.
3. Select **Authorize** near the top of the page. Paste the token into the
   HTTP Bearer value field and authorize. If the dialog asks for a scheme,
   use **Bearer**; paste the token itself, not the text `Bearer ` before it.
4. Close the dialog, expand **GET /api/{policy}/profile**, select **Try it
   out**, enter `C5` for `policy`, and select **Execute**.
5. A successful response contains the policy, subject, and role:

   ```json
   {
     "policy": "C5",
     "sub": "user-1042",
     "role": "user"
   }
   ```

Swagger UI also lets you try **GET /policies**. To compare validation
configurations, change the profile endpoint's `policy` value to `C0`, `C1`,
`C2`, `C3`, or `C4`.

### 3. Try the API with PowerShell

In a second PowerShell terminal, request a token and save it in `$token`:

```powershell
$response = Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8000/auth/token" `
  -ContentType "application/json" `
  -Body '{"username":"alice","password":"alice-pass"}'

$token = $response.access_token
```

Then call the protected C5 endpoint in that same terminal:

```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/api/C5/profile" `
  -Headers @{ Authorization = "Bearer $token" }
```

### 4. Try the API with curl, step by step

Run these commands in a second terminal while the server is running.

#### macOS or Linux

1. Request a token:

   ```bash
   curl -sS -X POST http://127.0.0.1:8000/auth/token \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"alice-pass"}'
   ```

   The JSON response includes `access_token`. Save its value in a shell
   variable (replace the placeholder with the actual token):

   ```bash
   TOKEN='<paste-access-token-here>'
   ```

2. Send the token to the protected endpoint:

   ```bash
   curl -i http://127.0.0.1:8000/api/C5/profile \
     -H "Authorization: Bearer $TOKEN"
   ```

#### Windows PowerShell

Use `curl.exe` explicitly in PowerShell. This command requests a token and
stores its `access_token` in `$token`:

```powershell
$loginResponse = curl.exe -sS -X POST "http://127.0.0.1:8000/auth/token" `
  -H "Content-Type: application/json" `
  -d '{"username":"alice","password":"alice-pass"}'
$token = ($loginResponse | ConvertFrom-Json).access_token
```

Then call the protected endpoint:

```powershell
curl.exe -i "http://127.0.0.1:8000/api/C5/profile" `
  -H "Authorization: Bearer $token"
```

To try another validation policy, replace `C5` in the URL with `C0`, `C1`,
`C2`, `C3`, or `C4`. Invalid credentials or a token rejected by the selected
policy return an error response.

After re-running the experiments, copy `results/paper/fig_*.pdf` into the
Overleaf `figures/` folder and paste the rows of `results/paper/tab_*.tex` into
the matching tables in `main.tex`, so the paper always shows your own
measurements.

## Results summary

The evaluation compares six JWT validation policies against synthetic token
scenarios using RS256 and HS256. In the recorded run, C5 accepted both valid
tokens and rejected all applicable invalid tokens: 24 in RS256 mode and 23 in
HS256 mode. By comparison, C0 accepted 22 invalid tokens in RS256 mode and 21
in HS256 mode. C2 rejected both valid test tokens because they carry an `aud` claim and no
expected audience was configured.

For C5, the mean validation time for the mixed workload was 89.69 µs per token
with RS256 and 42.50 µs with HS256. Timing depends on the machine and
environment; see the [timing results](./results/timing.json). The full
[decision matrix](./results/summary.json), [outcome figure](./results/paper/fig_outcomes.pdf),
and [timing figure](./results/paper/fig_timing.pdf) are also available.

## Paper

**Abstract:** We compare six PyJWT validation configurations against 26
labelled tokens. Signature and algorithm attacks were rejected by every
configuration that verifies signatures, but claim errors were not: the library
default rejected all valid tokens, and disabling the audience check let 9 of 24
invalid tokens through. An explicit RFC 8725 configuration accepted 2, and two
application-level checks reduced this to 0, at about 4% extra validation time.

## Environment of the reported run

Python 3.14.8, PyJWT 2.15.0, cryptography 50.0.1, Windows 11 (AMD64 laptop).
Timing numbers depend on hardware; decisions do not.

## Safety

All tests run locally against synthetic tokens and keys generated in memory.
No third-party system is contacted. The demo credentials in `app/main.py`
exist only for the prototype.
