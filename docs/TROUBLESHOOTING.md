# Local chalate waqt aam masle (Ubuntu)

## 1. `docker-compose up -d` -> "Error while fetching server API version"
Docker daemon chal nahi raha ya aap ko ijazat nahi.
```bash
sudo systemctl start docker && sudo systemctl enable docker
sudo usermod -aG docker $USER      # phir logout/login
sudo apt install docker-compose-v2 # naya `docker compose` (purana docker-compose 1.29 mat use karein)
docker compose up -d
```

## 2. `alembic` -> "No module named 'backend'"
Is zip mein fix hai (env.py ab path khud set karta hai). Warna: `PYTHONPATH=. alembic -c alembic.ini upgrade head`.

## 3. "password authentication failed for user aliguard" (port 5432)
Docker na chalne ki wajah se port 5432 par aap ka *system* Postgres jawab de raha hai, jis mein `aliguard` user/password alag hai.
Option A (recommended): `sudo systemctl stop postgresql`, phir `docker compose up -d` (Postgres 5432 par khud aa jayega).
Option B (system Postgres hi use karna ho):
```bash
sudo -u postgres psql -c "CREATE USER aliguard WITH PASSWORD 'aliguard_dev_pw';"
sudo -u postgres psql -c "CREATE DATABASE aliguard OWNER aliguard;"
```
phir `alembic -c alembic.ini upgrade head`. (User pehle se ho to `ALTER USER aliguard WITH PASSWORD 'aliguard_dev_pw';`)

## 4. "Rate limiter: Redis available nahi" warning
Redis nahi chal raha. Docker (upar) ya `sudo apt install redis-server && sudo systemctl start redis-server`. Dev mein sirf warning hai, lekin verify/2FA/rate limit Redis ke baghair poore kaam nahi karte.
