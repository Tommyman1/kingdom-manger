#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
[ -f .env ] || cp .env.example .env
if grep -q 'CHANGE_ME_TO_A_LONG_RANDOM_TOKEN' .env; then
  TOKEN=$(openssl rand -hex 32)
  sed -i "s/CHANGE_ME_TO_A_LONG_RANDOM_TOKEN/$TOKEN/" .env
  echo "Generated KM_API_TOKEN: $TOKEN"
  echo "Save this token in your password manager."
fi
docker network inspect proxy >/dev/null 2>&1 || { echo "Missing external Docker network: proxy"; exit 1; }
docker compose up -d --build
docker compose ps
