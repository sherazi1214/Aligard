# Deploy guide (Phase 4 + Frontend)

> **Frontend (Next.js) ab isi repo mein `frontend/` hai.** Teen zaroori baatein:
> 1. Backend ka `BASE_URL` aur `CORS_ORIGINS` = wahi domain jo user browser mein kholta hai (frontend ka domain).
> 2. Google redirect URI = `https://<domain>/api/gmail/callback`.
> 3. `BACKEND_URL` (frontend) **build se pehle** set hona chahiye (Next rewrites build par bake hote hain). VPS compose mein ye `http://web:8000` pehle se set hai.

Do raaste: **A) VPS + Docker (docker-compose.prod.yml + Caddy)** ya **B) Render (render.yaml)**.
Dono mein web aur worker alag process hain. Free tier jo sleep karta hai, worker ke liye mat lein (24/7 scanning band ho jati hai).

## Pehle (dono raaste)
1. Domain + DNS: `A` record server/Render ki taraf.
2. Secrets banayein (kahin commit/paste-log nahi):
   `python -m scripts.gen_secrets` (ya Docker se: `docker compose -f docker-compose.prod.yml run --rm web python -m scripts.gen_secrets`).
3. SMTP provider (verification/reset/alert emails). `EMAIL_BACKEND=smtp` production mein lazmi hai, warna app start nahi hoti.
4. Google Cloud Console: OAuth client ki **Authorized redirect URI** = `https://<domain>/api/gmail/callback`.
   `gmail.modify` restricted scope hai: public launch se pehle Google verification/security assessment lazmi (README Phase 3A).
5. `OPERATOR_NAME` aur `SUPPORT_EMAIL` set karein (Privacy/Terms pages par dikhte hain). Lawyer review karwayein.
6. Optional: `SENTRY_DSN`, `VT_API_KEY`, `OPENAI_API_KEY` (khali = band). Provider dashboard par apni spend limit bhi lagayein:
   AliGuard ki limits call-count ki hain, dollar ki nahi.

## A) VPS + Docker
```bash
git clone <repo> /opt/aliguard && cd /opt/aliguard
cp deploy/.env.prod.example .env.prod     # edit: DOMAIN, secrets, DATABASE_URL/REDIS_URL passwords
chmod 600 .env.prod
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```
- Firewall: sirf 22, 80, 443 kholein. DB/Redis kisi host port par publish nahi hain.
- `migrate` service har deploy par `alembic upgrade head` chalati hai; web/worker uske baad shuru hote hain.
- Caddy Let's Encrypt certificate khud leta hai (port 80/443 reachable hona chahiye).
- Backup cron: `17 3 * * * cd /opt/aliguard && ./scripts/backup.sh` (docs/BACKUP_RESTORE.md).
- Update: `git pull && docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build`.

## B) Render
Render par 4 cheezein banti hain: `aliguard-web` (API), `aliguard-frontend` (Next.js), `aliguard-worker`, DB + Redis.
Pehle `aliguard-web` deploy karein, uska public URL `aliguard-frontend` ke `BACKEND_URL` mein daalein, frontend deploy karein, phir
backend ke `BASE_URL`/`CORS_ORIGINS` ko **frontend ke URL** par set karke backend + worker dobara deploy karein.

**Known limit (Render):** `/api` yahan Next.js ke proxy se guzarta hai, aur backend rate-limit `X-Forwarded-For` ka aakhri hop leta hai.
Is liye backend sab users ko ek hi IP (frontend service) samajh sakta hai, aur global per-IP limit sab par ek saath lag sakti hai.
VPS + Caddy mein ye masla nahi (Caddy `/api` seedha backend ko deta hai). Render par launch se pehle ise staging mein zaroor check karein.

1. Repo Render se connect karein, **New > Blueprint**, `render.yaml` chunein. (File yahan Render par chalayi nahi gayi:
   plan names/schema dashboard mein validate karein.)
2. `sync: false` wale env vars dashboard mein bharein (BASE_URL, SECRET_KEY, ENCRYPTION_KEY, SMTP_*, GOOGLE_*, ...).
3. Health check path `/health` (liveness). `/health/ready` aur `/health/worker` ko sirf uptime monitor mein lagayein,
   warna DB/Redis ki chhoti si blip par Render web service restart karti rahegi.
4. Migrations `preDeployCommand` se chalte hain (paid plan). Managed Postgres ke automatic backups dashboard se verify karein.
5. `postgres://` / `postgresql://` URL app khud `postgresql+psycopg://` mein badal leti hai.

## Deploy ke baad verification (acceptance criteria)
```bash
curl -sI https://<domain>/api/auth/csrf | grep -i -E "strict-transport|content-security|x-frame"   # HSTS + CSP + headers
curl -s  https://<domain>/health/ready     # {"status":"ready","checks":{"database":true,"redis":true}}
curl -s  https://<domain>/health/worker    # {"status":"alive",...}  (worker ~1 cycle ke baad)
curl -s -o /dev/null -w "%{http_code}\n" https://<domain>/docs        # 404 (production mein band)
```
Phir: signup -> verify email -> login -> Gmail connect (test account) -> worker scan -> dashboard. Failure drills: docs/RUNBOOK.md.

## Uptime monitoring (UptimeRobot/Better Stack, 1-5 min)
| URL | Alert jab |
|---|---|
| `/health/ready` | 503 (DB ya Redis down) |
| `/health/worker` | 503 (worker band/stale/Redis unknown) |
| `/login` | non-200 (frontend zinda hai) |
Sentry alerts: `BUDGET_ALARM` messages aur unhandled exceptions.

## Load test (sirf apne staging par)
`python scripts/loadtest.py --base-url https://staging.example.com --concurrency 20 --duration 30`
Global rate limit 429 dega (expected); pure throughput ke liye staging par `GLOBAL_RATE_LIMIT_PER_MINUTE=0`.
