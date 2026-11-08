# Key rotation

| Secret | Kahan istemal | Badalne ka asar |
|---|---|---|
| `SECRET_KEY` | CSRF cookie signing | Sab CSRF tokens invalid: users ko page reload par naya token milta hai. Sessions/passwords par asar nahi |
| `ENCRYPTION_KEY` (Fernet) | Gmail tokens, TOTP secrets | Rotation procedure neeche; seedha badalne se sab Gmail/2FA decrypt nahi honge |
| `POSTGRES_PASSWORD`, `REDIS_PASSWORD` | DB/Redis | Dono jagah (service + DATABASE_URL/REDIS_URL) ek sath badlein, restart |
| Google client secret, SMTP, Telegram, Sentry, VT, OpenAI | integrations | Provider dashboard par naya banayein, env update, purana revoke |

Naye secrets: `python -m scripts.gen_secrets`. Secrets sirf platform env vars / `.env.prod` (chmod 600) mein; kabhi chat/commit/log mein nahi.

## SECRET_KEY
1. Naya value env mein, web restart. 2. Koi data migration nahi. Kam az kam saal mein ek bar, aur leak ke shak par foran.

## ENCRYPTION_KEY (zero-downtime)
1. Naya key banayein. 2. Env: `ENCRYPTION_KEY=<naya>` aur `ENCRYPTION_KEYS_OLD=<purana>` (comma separated agar kai). Web + worker restart.
   Ab naye encrypts naye key se, purane decrypts purani key se chalte hain (MultiFernet).
3. Pehle backup (`scripts/backup.sh`). 4. Dry-run: `python -m scripts.rotate_encryption_key --dry-run` (rotated = tamam secrets ki ginti, undecryptable = 0 hona chahiye).
5. Asli: `python -m scripts.rotate_encryption_key`. Docker: `docker compose -f docker-compose.prod.yml run --rm web python -m scripts.rotate_encryption_key`.
6. Verify: ek test user login+2FA, ek test Gmail account scan.
7. `ENCRYPTION_KEYS_OLD` khali karein, restart. Purani key ko backup mein kam az kam 1 backup-cycle (14 din) rakhein, phir destroy.
`undecryptable > 0` ho to un values ko chhuya nahi jata: wo user dobara connect/2FA setup kare; ya sahi purani key `ENCRYPTION_KEYS_OLD` mein daalein.

## Leak ka shak ho to
`ENCRYPTION_KEY` leak + DB leak = tokens padhe ja sakte hain: rotation ke saath saare Google refresh tokens revoke karwayein (users ko reconnect), TOTP dobara setup, aur `SECRET_KEY`/DB password bhi badlein.
