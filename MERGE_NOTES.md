# Merge notes (aliguard-phase4.zip + aliguard-frontend.zip)

## Kya kiya
- `aliguard-frontend/` ko `frontend/` ke naam se backend repo ke andar rakha (code ek line bhi nahi badla, sirf neeche wali cheezein).
- `deploy/Caddyfile`: `/api/*`, `/health*`, `/privacy`, `/terms`, `/static/*` -> backend; baqi sab -> frontend. HSTS dono par.
- `docker-compose.prod.yml`: `frontend` service (build arg `BACKEND_URL=http://web:8000`, healthcheck) + caddy ab frontend par bhi depend karta hai.
- `render.yaml`: `aliguard-frontend` web service.
- `.github/workflows/ci.yml`: `frontend` job (npm ci, typecheck, build) + frontend docker build.
- `frontend/next.config.js`: `/account` -> `/settings` redirect (backend ke privacy/terms pages ke nav mein /account link hai).
- `backend/app/main.py`: CORS `allow_methods` mein `PATCH` add (frontend `PATCH /api/settings` use karta hai; same-origin mein zaroori nahi, split-origin dev ke liye).
- `.env.example`: `BASE_URL=http://localhost:3000`. `.gitignore`, `frontend/.dockerignore`, README, docs/DEPLOY.md update.

## Jo check kiya (static)
- Frontend ke saare 30+ API calls (method + path) backend ke routes se match karte hain.
- Gmail OAuth callback `/dashboard?gmail=...` par redirect karta hai, frontend dashboard wahi param padhta hai.
- Verify/reset email links `/verify-email?token=` aur `/reset-password?token=` frontend ke pages se match karte hain.
- Compose / render / CI YAML parse hoti hain; `next.config.js` load hota hai; `main.py` compile hota hai.

## Jo YAHAN chala nahi (aap ke machine par karein)
- `pytest`, `ruff` (is sandbox mein Python packages/network nahi the) - backend mein sirf CORS ka ek word badla hai.
- `npm ci && npm run build && npm run typecheck` (network nahi tha).
- `docker compose ... up`, Caddy HTTPS, Render blueprint, CI jobs.
- Asli Gmail OAuth, SMTP, Telegram flow, browser mein UI ka haath se test.

## Known limit
- Render par rate-limit ka client-IP masla (docs/DEPLOY.md mein detail). VPS + Caddy recommended.
- Purana Jinja UI (`web/`) fallback ke taur par rakha hai; naye UI ke saath ye pages Caddy se nahi dikhte, lekin tests/CI unhein use karte hain.

## Portal merge (aliguard-portal-v21)
- `aliguard-portal/` ko `portal/` ke naam se is project mein rakha (code unchanged). Alag app hi rahi, kyunke portal SQLite + apna session/login rakhta hai aur full app Postgres + apna auth; dono SSO token se jure hain (sso.py pehle se full app mein tha).
- `portal/Dockerfile` naya; `docker-compose.prod.yml` mein `portal` service + `portal_data` volume; `deploy/Caddyfile` mein `{$PORTAL_DOMAIN}` block; `.env.prod.example` + README update.
- Prod mein `SSO_SHARED_SECRET` compose se portal ko `${SSO_SHARED_SECRET}` milta hai; `.env.prod` mein wahi value rakhein jo web ke liye hai (env_file se).
- Chalaya nahi: docker build, compose up, Caddy. Sirf static check + YAML parse.

## Buy ke baad seedha Connect Gmail
- `backend/app/auth/router.py` (`/api/auth/sso`): service == "gmail" ho to redirect `/dashboard?connect=gmail`.
- `frontend/.../dashboard/page.tsx`: `?connect=gmail` par, agar koi inbox connected nahi (aur Gmail configured), ek bar automatically `/api/gmail/connect` chala kar Google permission screen par bhejta hai. Pehle se inbox connected ho to kuch nahi karta.
- `tests/test_sso_handoff.py` ka assertion update. Chalaya nahi (pytest/npm yahan nahi).

### Update: auto-redirect ki jagah welcome card
- `?connect=gmail` par ab dashboard ke top par "Connect Gmail" welcome card aata hai (auto-redirect nahi). Button -> Google.
- `backend/app/gmail/router.py`: OAuth `prompt=select_account consent` taake Google device ke saare Gmail accounts ka chooser dikhaye. Test update.

## Security hardening (OWASP)
Tafseel docs/SECURITY_CHECKLIST.md mein. Naye env: portal ke liye SMTP_HOST/PORT/USER/PASSWORD/FROM, PORTAL_PAYMENTS_TEST_MODE (default 0). Verified: portal ka end-to-end security test chala (signup -> buy 403 -> verify -> buy ok, token mein verified claim, single-use link, production mein buy 503). Full app ke pytest/npm yahan nahi chale.
