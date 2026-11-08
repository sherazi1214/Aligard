# AliGuard - Full Stack (Backend + Frontend merged)

Ye ek hi project hai: **FastAPI backend (Phase 0-4)** + **Next.js frontend (Sentinel UI)**.

```
backend/    FastAPI API (auth, gmail, scans, settings, check, worker)
engine/     Detection engine (ML + heuristics + reputation + LLM)
frontend/   Next.js 14 UI (landing, auth, dashboard, scanner, settings)   <-- NAYA
portal/     Portal (FastAPI+SQLite+plain JS): signup/Google login, plans, Cyber World, SSO handoff   <-- MERGED
web/        Purana Jinja2 UI (fallback; /privacy aur /terms abhi bhi yahin se serve hote hain)
deploy/     Caddyfile (frontend + backend routing), .env.prod.example
docs/       DEPLOY, RUNBOOK, BACKUP_RESTORE, KEY_ROTATION, SECURITY_CHECKLIST
tests/      pytest (backend)
```

## Kaise jura hua hai
Browser sirf **ek domain** se baat karta hai. Pages (`/`, `/login`, `/dashboard`, `/scanner`, `/settings` ...) Next.js dete hain;
`/api/*`, `/health*`, `/privacy`, `/terms`, `/static/*` backend se aate hain (VPS par Caddy seedha, warna Next ke rewrites se).
Isliye session cookie, CSRF aur Gmail OAuth callback bina CORS ke chalte hain.

## Local par poora stack chalana (4 terminal / tab)
```bash
# 0) Postgres + Redis
docker compose up -d

# 1) Backend
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cp .env.example .env          # BASE_URL=http://localhost:3000, CORS_ORIGINS=http://localhost:3000 pehle se set hain
alembic -c alembic.ini upgrade head
uvicorn backend.app.main:app --port 8000

# 2) Worker (alag terminal)
python -m backend.app.worker

# 3) Frontend (alag terminal)
cd frontend && cp .env.example .env.local     # BACKEND_URL=http://127.0.0.1:8000
npm install && npm run dev                    # http://localhost:3000   <-- yahan se use karein
```
Google Console redirect URI (local): `http://localhost:3000/api/gmail/callback`.
Dev mein `EMAIL_BACKEND=console`: verify/reset link backend ke terminal log mein print hota hai.

## Production (VPS + Docker, recommended)
```bash
cp deploy/.env.prod.example .env.prod      # DOMAIN, secrets, passwords bharein
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```
Services: `caddy` (HTTPS) -> `frontend` + `web` (API), `worker`, `migrate`, `db`, `redis`. Poori guide: `docs/DEPLOY.md`.

---


Structure:
```
backend/   FastAPI API (config, db, redis, health, security headers)
engine/    Detection engine (Phase 1)
web/       Frontend (Jinja2 + CSP-safe JS)
clients/   .exe aur mobile app (Phase 5-6)
tests/     pytest
```

## Local chalane ke steps

1. **Docker Desktop** install karo, phir Postgres + Redis chalao:
   ```
   docker compose up -d
   ```
2. Virtual environment aur dependencies:
   ```
   python -m venv .venv
   .venv\Scripts\activate        # Windows
   source .venv/bin/activate     # Linux/Mac
   pip install -r requirements-dev.txt
   ```
3. `.env` banao: `copy .env.example .env` (Windows) ya `cp .env.example .env`
4. Server:
   ```
   uvicorn backend.app.main:app --reload
   ```
5. Check: http://localhost:8000/health  aur  http://localhost:8000/health/ready
   (dono ok aur ready ho to Phase 0 done). API docs: http://localhost:8000/docs

## Quality checks (commit se pehle)
```
ruff check .
pytest -q
pip-audit -r requirements.txt
```

## Security rules (hamesha)
- `.env` kabhi commit nahi. Production mein SECRET_KEY 32+ random chars (warna app start nahi hogi).
- Naye packages add karte waqt version pin karo aur `pip-audit` chalao.
- Production mein `/docs` band rehta hai.

## Phase 1: Detection engine

```python
from engine import analyze, EmailInput, Engine
from engine.parsing import from_raw_email

r = analyze(from_raw_email(open("mail.eml", "rb").read()))   # bundled ML + heuristics
r.verdict, r.score, r.confidence, r.reasons, r.defanged_urls, r.degraded
```
Reputation + LLM ke saath (keys `.env` se lo, code mein nahi):
```python
from engine.reputation import VirusTotalProvider, LocalFeed
from engine.llm import OpenAIProvider
eng = Engine.default(
    reputation=[LocalFeed.from_file("urlhaus", "feeds/urlhaus.txt"), VirusTotalProvider(VT_KEY)],
    llm=OpenAIProvider(OPENAI_KEY, model="gpt-4o-mini"),  # model naam deploy se pehle check karo
)
```
Commands:
```
python -m engine.train                 # model dobara train (synthetic) ya --csv real.csv
python -m engine.evaluate              # sample emails par report
pytest -q                              # 80 tests
```
**Pehle `engine/METRICS.md` zaroor padho**: bundled model synthetic data par hai.

Design guarantees (har ek test + mutation-check se saabit):
- ML akeli kabhi PHISHING nahi, sirf SUSPICIOUS (heuristics ki corroboration chahiye)
- LLM ka "SAFE" strong evidence (feed hit, VT>=5, strong heuristics) ko kam nahi karta
- LLM output strict JSON validate hota hai, kharab output ignore; email random delimiters mein
- Jaali `Authentication-Results` headers ignore (sirf trusted server ka header maana jata hai)
- Model file load se pehle SHA-256 verify; sklearn version mismatch par load nahi
- Koi network/layer fail ho to `degraded=True`, crash nahi; engine URLs ko khud visit nahi karta

## Phase 2: Web auth system

Signup, email verification, login, logout, forgot/reset password, TOTP 2FA, audit log.
UI: `web/templates` (Jinja2) + `web/static` (CSP-safe, inline script nahi). Logic: `backend/app/auth/`.

Setup:
```
cp .env.example .env            # ENCRYPTION_KEY production mein lazmi (command .env.example mein)
docker compose up -d
alembic -c alembic.ini upgrade head
uvicorn backend.app.main:app --reload     # http://localhost:8000/signup
```
Dev mein `EMAIL_BACKEND=console`: verify/reset links server log mein print hote hain (sirf dev; production mein SMTP lazmi, warna app start nahi hoti).

API (`/api/auth/*`, har POST par `X-CSRF-Token` header lazmi, token `aliguard_csrf` cookie se):
`signup, verify-email, resend-verification, login, login/2fa, logout, logout-all, forgot-password, reset-password, change-password, 2fa/setup, 2fa/enable, 2fa/disable, me, csrf`

Security design:
- Argon2id; password min 12, common-list + HaveIBeenPwned k-anonymity (sirf SHA-1 ke 5 chars bahar jate hain)
- Email tokens: 32 random bytes, DB mein sirf SHA-256, single-use (atomic UPDATE), verify 24h / reset 20 min, naya token purane ko invalid
- Sessions server-side, DB mein hash, HttpOnly + SameSite=Lax (+Secure production mein), login par rotation, idle 30 min / absolute 24h, logout/reset/password-change par revoke
- CSRF: signed double-submit cookie + Origin check
- Brute force: per-IP + per-email Redis limits (maujood na hone wali email par bhi) + DB exponential account lockout; lock hone par bhi generic error
- Enumeration: signup/forgot/resend ka response hamesha ek jaisa; login par dummy Argon2 verify; reset/forgot ka kaam background mein
- 2FA: secret Fernet se encrypted, TOTP replay block, 8+ recovery codes (10, hashed, single-use), 5 galat tries par pending session khatam
- Audit log: login success/fail, lockout, password change/reset, 2FA on/off, logout (IP ke saath, secrets nahi)

Known limits (honest list):
- Redis down ho to rate limiter fail-open hota hai (log hota hai); DB lockout phir bhi chalta hai
- HIBP down ho to breach check skip (fail-open, log)
- Account lock hone par user ko generic error milta hai (enumeration se bachne ke liye), "locked" nahi bataya jata
- Email delivery asal SMTP provider ke saath test nahi hui (sirf mocked); production se pehle apne provider se try karein
- Frontend JS ke browser tests nahi (sirf static checks: inline script/innerHTML nahi); UI haath se ek bar chalayein
- Token consume ka race-guard (atomic UPDATE) concurrent requests se test nahi hua
- Rate-limit/lockout ki values `.env` se tune hoti hain (config.py dekhein)

## Phase 3A: Gmail connect + Dashboard + manual check

Phase 3A ne Gmail OAuth connect/disconnect, DB tables, dashboard UI, scan log API aur manual Link/Message check add kiye.
Phase 3B ka implementation neeche documented hai: background worker, labels/quarantine, Restore + feedback, alerts, settings,
whitelist aur "Delete my data". Ye features code mein add hue hain, lekin unki full live Gmail/Telegram end-to-end testing
production credentials ke baghair abhi bhi operator ko karni hogi.

### Setup (Google Cloud Console)
1. Project banao, **Gmail API** enable karo.
2. OAuth consent screen (External), scope `.../auth/gmail.modify`, apne test Gmail accounts "Test users" mein daalo.
3. Credentials > OAuth client ID > type **Web application**, Authorized redirect URI:
   `http://localhost:8000/api/gmail/callback` (production: `https://tumhara-domain/api/gmail/callback`).
4. `.env` mein `GOOGLE_CLIENT_ID` aur `GOOGLE_CLIENT_SECRET` daalo (code mein kabhi nahi), phir:
```
alembic -c alembic.ini upgrade head      # migration 0002: gmail_accounts, scans, whitelist, alerts_settings
uvicorn backend.app.main:app --reload    # http://localhost:8000/dashboard
```
`ENCRYPTION_KEY` (Fernet) tokens encrypt karti hai; production mein lazmi. **Ye key kho di to saare Gmail tokens bekar**
(users ko dobara connect karna parega); backup alag jagah rakho.

### Google verification (restricted scope) - public launch se pehle
`gmail.modify` Google ka **restricted scope** hai. Sirf apne/test users ke liye "Testing" mode kafi hai (limit: ~100 test users,
aur Google ki policy ke mutabiq Testing mode mein refresh tokens ~7 din mein expire ho sakte hain, is liye user ko dobara
connect karna parega; ye policy Google ke current docs se dobara confirm karein). Dusre logon ke liye public karne se pehle
OAuth app verification aur **third-party security assessment (CASA)** lazmi hai, jis mein hafte/mahine aur kharcha lag sakta hai.
Privacy policy page aur scope ki wazahat bhi chahiye. Ye kaam code se nahi hota, isliye Phase 4 se pehle shuru kar dein.

### API
| Endpoint | Kaam |
|---|---|
| `GET /api/gmail/accounts` | Apne connected accounts (tokens kabhi wapas nahi aate) |
| `POST /api/gmail/connect` | OAuth URL (PKCE S256 + state); CSRF lazmi |
| `GET /api/gmail/callback` | Google yahan redirect karta hai; sirf fixed code ke saath `/dashboard?gmail=...` |
| `POST /api/gmail/accounts/{id}/disconnect` | Tokens delete + Google revoke (best-effort) |
| `GET /api/scans`, `/api/scans/stats`, `/api/scans/{id}` | Dashboard data (page, page_size<=50, verdict, q, account_id) |
| `POST /api/check` | Link/Message check: login + CSRF + per-user rate limit + body size limit; result store nahi hota |

### Security design
- **OAuth**: authorization code + PKCE (S256). `state` random, Redis mein single-use, **browser cookie se bandha** (login-CSRF) aur
  usi user ki session se match hona lazmi. Redis down ho to connect band (fail-closed). Sirf `gmail.modify` scope maanga jata hai;
  agar user ye ijazat na de to token turant revoke ho jata hai.
- **Tokens**: Fernet se encrypted DB mein; API/logs mein kabhi nahi. Disconnect par DB se delete chahe Google revoke nakam ho.
- **Isolation**: har query mein `user_id`; doosre user ka scan/account **404** (existence leak nahi), tests mein saabit.
- **XSS**: sender/subject/reasons attacker-controlled; UI sirf `textContent` se dikhati hai, URLs defanged store hote hain,
  CSP strict (inline script/style nahi). `dashboard.js` mein innerHTML waghera ka static test hai.
- Email **body store nahi hoti**; scans table mein sirf sender, subject, verdict, reasons, defanged URLs.
- `scans` ka unique key `(gmail_account_id, gmail_message_id)` hai (spec ka "per user" nahi): Gmail message id mailbox ke andar
  unique hota hai, aur ek user ke 3 accounts tak ho sakte hain.

### Known limits (Part A, honest list)
- **Asli Google ke saath end-to-end test nahi hua**: tests mein Google ki calls mock hain. Pehli bar haath se connect/disconnect
  chala kar dekhein (consent screen, refresh token milna, revoke).
- Browser mein dashboard UI ka automated test nahi (sirf API tests + static JS checks). Haath se: tabs, filter, pagination,
  detail, link/message check, disconnect.
- Scan log Part B tak khali. `quarantined` stat `action_taken` se aati hai jo worker likhega.
- `alerts_settings` table bani hai par uska UI/use Part B mein.
- `/api/check` ka body-size cap stream mein lagta hai; reverse proxy par bhi `client_max_body_size` (nginx) lagayein.
- Redis down ho to rate limiter fail-open (pehle jaisa); `/api/check` phir bhi login + size limit se bacha hai.
- Migration 0002 asli Postgres par CI smoke test se chalti hai, tests SQLite par hain; dono ka farq (JSON, UUID) CI mein pakda jata hai.


## Phase 3B: Background scanning, restore, feedback and settings

Worker ko web server se alag process mein chalayein:

```bash
python -m backend.app.worker --once       # due accounts ka aik cycle
python -m backend.app.worker --once --force # next_run_at ko ignore karke test cycle
python -m backend.app.worker               # continuous scheduler
```

Worker Redis per-account lock, bounded concurrency, Gmail history bookmark, duplicate-scan unique constraint,
retry/backoff aur pending action reconciliation use karta hai. Email body database mein store nahi hoti. Gmail OAuth
revoke/expire ho to account `needs_reauth` hota hai; user dashboard se usi Gmail ko dobara connect kar sakta hai.

New APIs (mutating requests par CSRF required):

| Endpoint | Kaam |
|---|---|
| `POST /api/scans/{id}/restore` | Quarantine se Inbox mein restore |
| `POST /api/scans/{id}/feedback` | `not_phishing` feedback record |
| `GET /api/settings` | Apni alerts, thresholds aur whitelist |
| `PATCH /api/settings` | Alert preferences / thresholds update |
| `POST /api/settings/whitelist` | Sender/domain whitelist entry |
| `DELETE /api/settings/whitelist/{id}` | Apni whitelist entry remove |
| `POST /api/settings/telegram/link` | Single-use Telegram link generate |
| `DELETE /api/settings/telegram/link` | Telegram unlink |
| `DELETE /api/settings/data?confirm=DELETE_MY_DATA` | Irreversible account/data deletion |

**Production caution:** Gmail actions aur OAuth ko apne controlled test account par end-to-end verify karein. ML bundled model abhi
synthetic dataset par hai; quarantine thresholds conservative hain, lekin production guarantee nahi. CI tests aur real Google OAuth
verification pass hone tak AliGuard ko fully production-ready ya cloud-proof nahi samajhna chahiye.

## Phase 4: Hardening + Deploy
- Deploy: `docs/DEPLOY.md` (VPS+Docker+Caddy ya Render), env: `deploy/.env.prod.example`, `.env.example`.
- Operations: `docs/RUNBOOK.md` (incidents, failure drills, rollback), `docs/BACKUP_RESTORE.md`, `docs/KEY_ROTATION.md`.
- Security: `docs/SECURITY_CHECKLIST.md` (OWASP Top 10 + launch gate).
- Observability: JSON masked logs, optional Sentry, `/health`, `/health/ready`, `/health/worker`.
- Limits: per-IP global rate limit, paid API (VirusTotal/OpenAI) daily call budgets, data retention (`SCAN_RETENTION_DAYS`).
- Scripts: `scripts/gen_secrets.py`, `backup.sh`, `restore.sh`, `restore_test.sh`, `rotate_encryption_key.py`, `loadtest.py`.
- Honest status: `PHASE4_PROGRESS.md` (kya test hua, kya live verify baqi).

## Phase 5: Portal SSO handoff (`aliguard-portal` -> is app)
`GET /api/auth/sso?token=...` -- `aliguard-portal` (marketing/signup + buy-a-plan site) is route
par ek short-lived, signed, single-use token bhejta hai jab user sign-in/signup/purchase kar leta
hai. Hum password dobara nahi puchte -- bas HMAC signature (shared secret) aur expiry check karte
hain, phir usi email ka account yahan bana/dhoond kar session de dete hain. Kharidi hui service
`entitlements` table mein 30-din ke liye likh di jati hai.

- Shared secret: `SSO_SHARED_SECRET` (dono apps mein **wahi** value; `.env.example` dekhein).
  Khali ho to `/api/auth/sso` 404 deta hai (feature off).
- Replay se bachao: token ka `nonce` `sso_nonces` table mein ek hi bar insert ho sakta hai.
- Migration: `0004_sso_entitlements.py` (`entitlements`, `sso_nonces` tables).
- Tests: `tests/test_sso_handoff.py`.
- Portal side ka code (token banana): `aliguard-portal/backend/main.py` -> `make_sso_token()`.


## Portal (aliguard-portal ab isi project mein)
`portal/` alag chhoti app hai (apna login, plans, Cyber World page). Plan khareedne par signed one-time SSO token se
user seedha is app ke dashboard mein aa jata hai. Dono ko **same `SSO_SHARED_SECRET`** chahiye.

Local par:
```bash
cd portal && python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
SSO_SHARED_SECRET=<same 32+ chars> FULL_APP_URL=http://localhost:3000 uvicorn backend.main:app --port 8001
```
(Portal 8001 par, backend 8000 par, frontend 3000 par; `BASE_URL` portal ka apna hai.)

Production: `docker-compose.prod.yml` mein `portal` service aur Caddy mein `PORTAL_DOMAIN` block shamil hai.
`.env.prod` mein `PORTAL_DOMAIN` aur `SSO_SHARED_SECRET` set karein.
# Aligard
