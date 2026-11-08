#!/usr/bin/env bash
# Backup ka restore TEST: scratch database mein restore karke check, phir scratch drop. Production DB ko nahi chhuta.
# Usage: ./scripts/restore_test.sh backups/aliguard-YYYYMMDDTHHMMSSZ.dump
set -euo pipefail
cd "$(dirname "$0")/.."
dump="${1:?backup file ka path dein}"
COMPOSE=(docker compose -f docker-compose.prod.yml --env-file .env.prod)
[ -f "$dump.sha256" ] && sha256sum -c "$dump.sha256"
scratch="aliguard_restore_test"
"${COMPOSE[@]}" exec -T db psql -U aliguard -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS $scratch" -c "CREATE DATABASE $scratch"
trap '"${COMPOSE[@]}" exec -T db psql -U aliguard -d postgres -c "DROP DATABASE IF EXISTS '"$scratch"'" >/dev/null' EXIT
"${COMPOSE[@]}" exec -T db pg_restore -U aliguard -d "$scratch" --no-owner --exit-on-error < "$dump"
tables=$("${COMPOSE[@]}" exec -T db psql -U aliguard -d "$scratch" -tA -c "select count(*) from information_schema.tables where table_schema='public'")
rev=$("${COMPOSE[@]}" exec -T db psql -U aliguard -d "$scratch" -tA -c "select version_num from alembic_version")
users=$("${COMPOSE[@]}" exec -T db psql -U aliguard -d "$scratch" -tA -c "select count(*) from users")
echo "Restore OK: tables=$tables alembic_revision=$rev users=$users"
[ "$tables" -ge 10 ] || { echo "FAIL: tables kam hain"; exit 1; }
