# AliGuard Portal (backend + frontend)
FastAPI + SQLite backend, plain HTML/CSS/JS frontend (no npm needed). One server runs both.

## Run
    python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
    pip install -r requirements.txt
    uvicorn backend.main:app --reload                      # http://127.0.0.1:8000

## What it does
- Landing page, then **Create account** with username, Gmail, password and confirm password (eye icons show or hide each password), or **Continue with Google**.
- After sign-in or sign-up you enter the animated **Cyber World** page (`/world`, members only, enforced on the server): live radar, simulated threat feed, shield plans, link lab and cyber academy.
- Argon2id password hashing, server-side sessions in HttpOnly cookies, header-based CSRF guard, rate limits, strict CSP.

## Enable Google sign-in
1. Google Cloud Console, then APIs and Services, then Credentials, then create an **OAuth client ID** (Web application).
2. Add the authorized redirect URI: `http://127.0.0.1:8000/api/google/callback` (use your real `BASE_URL` in production).
3. Start the server with:

        GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... BASE_URL=http://127.0.0.1:8000 uvicorn backend.main:app

Without these variables the Google button shows a friendly "not set up" message.

## Hand off into the AliGuard app (aliguard-full)
Once a user buys a plan here, they're redirected straight into the signed-in dashboard of the
full product (`aliguard-full`) — no second login. This works via a short-lived, signed, single-use
token (not a shared cookie, so the two apps can be on separate subdomains or even separate hosts).

1. Generate one shared secret: `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
2. Set it as `SSO_SHARED_SECRET` on **both** apps' environments — it must be identical on each side.
3. Set `FULL_APP_URL` here to the full app's base URL (e.g. `https://app.example.com`).
4. On `aliguard-full`, set `SSO_SHARED_SECRET` the same way (see its own README/`.env.example`).

Without `SSO_SHARED_SECRET` set here, `/api/buy/*` and `/api/sso-url` simply omit the handoff link
and behave exactly as before (stay on the portal).

## Not built yet (before production)
- Real payments: `/api/buy` is TEST MODE. With real payments only a signed provider webhook should activate a service.
- Email verification and 2FA. Password reset links are printed to the server console in dev mode.
- Rate limits live in memory (reset on restart); use Redis in production.
- Admin panel, Privacy Policy and Terms. Set `APP_ENV=production` behind HTTPS (Secure cookie and HSTS).
- Behind a reverse proxy, `request.client.host` is the proxy's address; trust proxy headers correctly.
- The statistics and threat feed on the Cyber World page are simulated for illustration.
