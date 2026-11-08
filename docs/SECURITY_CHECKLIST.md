# Security checklist (OWASP Top 10, 2021) - AliGuard

Status: **T** = automated test maujood, **C** = code mein hai par live verify chahiye, **L** = sirf live/deploy par ho sakta hai.
Ye khud-assessment hai, independent penetration test nahi.

| # | Risk | Kya hai | Status |
|---|---|---|---|
| A01 | Broken access control | Har query mein `user_id` filter; doosre user ka resource 404; CSRF har mutation par; restore/settings/whitelist ownership | T (`test_scans_isolation`, `test_phase3b_settings_actions`) |
| A02 | Cryptographic failures | Argon2id passwords; Fernet (Gmail/2FA); tokens DB mein hash; HTTPS+HSTS (production), Secure/HttpOnly cookies | T (config/headers), **L** (TLS certificate asli domain par) |
| A03 | Injection / XSS | SQLAlchemy parameterized; Jinja autoescape; email fields sirf `textContent`; strict CSP (no inline script) | T (XSS, CSP tests) |
| A04 | Insecure design | Per-IP/per-account rate limits + lockout; global limiter; paid-API budgets; email body store nahi; URLs kabhi fetch nahi | T |
| A05 | Security misconfiguration | Production mein `/docs` band; weak SECRET/ENCRYPTION/SMTP par start nahi; CORS wildcard nahi; koi debug/admin route nahi; DB/Redis publish nahi | T (`test_no_debug_or_admin_routes_exist`), **L** (firewall, Caddy) |
| A06 | Vulnerable components | Pinned versions (>=14 din purane), `pip-audit` CI mein, Dependabot nahi | T/C. Docker base image scan abhi nahi (trivy/grype add karna baqi) |
| A07 | Identification & auth failures | Breach-password check, lockout, 2FA TOTP + recovery codes, session rotate/revoke, reset enumeration-safe | T (`test_auth_*`) |
| A08 | Software & data integrity | ML model hash verify; joblib (pickle nahi); CI actions version tags par (commit SHA par pin nahi) | T (model hash), C |
| A09 | Logging & monitoring | JSON masked logs, Sentry (scrubbed), `/health/*`, worker heartbeat, `BUDGET_ALARM` | T (masking), **L** (uptime monitor/alert routing set karna) |
| A10 | SSRF | Email links kabhi fetch nahi hote; outbound sirf fixed hosts (Google, VT, OpenAI, Telegram, HIBP) | C |

## Cookie / header verify (live, browser DevTools ya curl)
- Session cookie: `HttpOnly; Secure; SameSite=Lax`. CSRF cookie `Secure`.
- Response headers: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options`, `Referrer-Policy`.

## Launch se pehle (gate)
- [ ] `ruff`, `pytest`, `pip-audit` clean (CI)
- [ ] gitleaks CI clean; `.env*` repo mein nahi
- [ ] Production env checklist (docs/DEPLOY.md) + deploy ke baad curl checks
- [ ] Backup + restore test kiya (docs/BACKUP_RESTORE.md)
- [ ] Failure drills staging par chalaye (docs/RUNBOOK.md)
- [ ] Uptime monitor `/health/ready` + `/health/worker`, Sentry alert
- [ ] Privacy/Terms lawyer review, `OPERATOR_NAME`/`SUPPORT_EMAIL`
- [ ] Google OAuth verification (restricted scope)
- [ ] Provider-side spend limits (OpenAI/VT) set
- [ ] Docker image vulnerability scan
- [ ] Kam az kam ek independent security review / pentest (public launch se pehle)


## OWASP Top 10 audit (portal merge) - kya fix hua
| OWASP | Masla | Fix |
|---|---|---|
| A01/A07 Broken access / auth | Portal par kisi ki bhi email se signup (verify ke baghair) -> SSO se full app mein us email ke ASLI account mein login (account takeover) | Portal par email verification (link, single-use). SSO token mein `verified` claim; full app unverified token reject karti hai |
| A07 | SSO se 2FA bypass | 2FA wale account ko SSO session nahi milti; plan activate hota hai, phir normal login (password + code) |
| A07 | Pre-hijack: attacker victim ki email se password ke sath account banaye, victim baad mein Google se aaye | Google login par unverified row ka password random + sab sessions delete |
| A04 Insecure design | Portal `/api/buy` bina payment plan de deta tha | Production mein `PAYMENTS_TEST_MODE=0` (503). Asli payment webhook abhi baqi hai |
| A05 Misconfig | Portal proxy ke peeche sab users ek IP (rate limit shared); Next pages par framing/base-uri headers nahi | `--forwarded-allow-ips`; Next par frame-ancestors/base-uri/object-src/form-action headers; portal par Permissions-Policy, COOP |
| A05/A09 | SQLite connections close nahi hote (fd leak = DoS); expired sessions/tokens jama | `db()` ab hamesha close karta hai; startup par expired rows saaf |
| A02 | SSO secret kamzor ho sakta tha | Portal 32 se kam chars ke secret par handoff band |
| A07 | Production mein password-reset email kabhi nahi jati thi | SMTP mailer (SMTP_HOST...), tokens console mein sirf dev mein |

Pehle se theek tha (full app): Argon2id, CSRF double-submit + Origin, account lockout, Redis rate limit, Fernet-encrypted Gmail tokens, PKCE, strict CSP, gitleaks + pip-audit CI, non-root Docker.

Abhi BAQI (honest list): asli payment + signed webhook, portal rate limit in-memory (Redis par le jayen), portal mein admin/2FA nahi, Next pages par full script-src CSP (nonce chahiye), penetration test aur dependency audit (`npm audit`) apni machine par.
