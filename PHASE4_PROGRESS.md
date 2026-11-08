# Phase 4 - code + deploy config + docs

## Bana aur test hua (ruff clean, 206 tests pass, pip-audit clean)
- JSON structured logging + secret/PII masking; masked access log (query string/tokens kabhi nahi); uvicorn access log band.
- Optional Sentry (`SENTRY_DSN`): request body/cookies/query/locals scrub.
- Worker heartbeat + `GET /health/worker` (stale/unknown => 503); worker mein hourly data-retention purge (`SCAN_RETENTION_DAYS`).
- Global per-IP rate limit (`GLOBAL_RATE_LIMIT_PER_MINUTE`) + Redis circuit breaker (Redis down => fail-open, slow nahi).
- Paid API budget: VirusTotal/OpenAI daily call caps (global + per-user), 80%/100% alarm, Redis down => fail-closed. Keys khali => layers band.
- Encryption key rotation (`ENCRYPTION_KEYS_OLD`, `python -m scripts.rotate_encryption_key`), `postgres://` URL normalization.
- Privacy Policy / Terms pages (/privacy, /terms, footer links; enabled providers ke hisaab se text).
- Failure-drill tests: Redis down, DB down (generic 500, no leak), Gmail 429 retry/transient.
- Deploy files: Dockerfile (healthcheck), docker-compose.prod.yml + Caddy (VPS), render.yaml, backup/restore/restore_test scripts, gen_secrets, loadtest, CI (gitleaks, docker build, compose validate).

## Docs (bane)
- docs/DEPLOY.md, RUNBOOK.md, BACKUP_RESTORE.md, KEY_ROTATION.md, SECURITY_CHECKLIST.md (OWASP) aur README update.
- Docs ke commands/steps yahan asli server par chalaye nahi gaye; pehli deploy par inhein verify karke fix karein.

## Test NAHI hua (live karna hoga)
- render.yaml Render par, docker-compose.prod.yml, Caddy HTTPS, CI gitleaks/docker jobs: yahan chale nahi.
- backup.sh / restore_test.sh asli Postgres par chale nahi (sirf bash syntax check).
- Asli load test, aur Redis/DB band karne ke live drills staging par.
- Sentry, VirusTotal, OpenAI, SMTP live credentials ke saath.
- Privacy/Terms lawyer review ke baghair template hain.

## v3 (sandbox + postmortem + naye layers)
- engine/sandbox.py (Playwright link detonation + SSRF guard), engine/attachments.py, engine/qr.py, engine/domainintel.py,
  engine/postmortem.py. Migration 0006 (scans.postmortem). Dashboard "Postmortem" panel. Docs: docs/SANDBOX.md, docs/FEATURES.md.
- Test hua: pytest 283 pass (2 deselected: sklearn 1.8 vs 1.9.1 model-version check, sirf is sandbox ka masla), ruff clean,
  frontend tsc + next build pass, asli Chromium se local fake-phishing page.
- Test NAHI hua: asli phishing URLs, RDAP live, production Docker mein Chromium, Postgres par migration 0006,
  browser mein UI ka haath se test, load (sandbox concurrency).
