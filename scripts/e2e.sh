#!/usr/bin/env bash
# Local end to end run: builds identity, runs identity-setup (an admin when none exists, two clients with
# random ids), starts the server and runs scripts/e2e.py against it. Safe to repeat.
#
# Needs a Postgres with the identity schema (db-migration V1..V8) and a Redis; point at them with
# POSTGRES_* and REDIS_* (defaults of gocommon otherwise).
set -euo pipefail
cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'kill "${pid:-0}" 2>/dev/null || true; rm -rf "$tmp"' EXIT

export ENV=local HTTP_PORT=${HTTP_PORT:-18080} PORT=${PORT:-19090}
export IDENTITY_ISSUER=http://localhost:$HTTP_PORT
export IDENTITY_SIGNING_KEY_FILE=$tmp/k1.pem IDENTITY_SIGNING_KEY_ID=k1
export IDENTITY_MFA_KEY="k1:$(openssl rand -base64 32)"
export SETUP_ADMIN_PASSWORD='Correct-Horse-Battery-9'
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/k1.pem" 2>/dev/null

go build -o "$tmp/identity" ./cmd/identity
go build -o "$tmp/identity-setup" ./cmd/identity-setup

suf=$(openssl rand -hex 3); export WEB_CLIENT=webgk-$suf GK_CLIENT=gk-$suf
secret=$(openssl rand -hex 16)
# keep_password: the e2e signs in with the given password (a real setup forces a change)
SETUP_CONFIG=$(cat <<EOF
{"admin":{"email":"admin@example.com","keep_password":true},
 "clients":[
  {"id":"$WEB_CLIENT","type":"public","resource":"gatekeeper","redirect_uris":["http://localhost:3000/cb"]},
  {"id":"$GK_CLIENT","type":"confidential","resource":"gatekeeper","secret_env":"E2E_CLIENT_SECRET",
   "grants":["client_credentials","urn:ietf:params:oauth:grant-type:token-exchange"],"roles":["admin"]}],
 "exchange_policies":[{"client":"$GK_CLIENT","audience":"courier","max_depth":1}]}
EOF
) E2E_CLIENT_SECRET=$secret "$tmp/identity-setup"

"$tmp/identity" >"$tmp/identity.log" 2>&1 &
pid=$!
for _ in $(seq 1 50); do curl -fs "$IDENTITY_ISSUER/healthz" >/dev/null && break; sleep 0.2; done

ISSUER=$IDENTITY_ISSUER EMAIL=admin@example.com PASSWORD=$SETUP_ADMIN_PASSWORD GATEKEEPER_SECRET=$secret \
  python3 scripts/e2e.py || { tail -30 "$tmp/identity.log"; exit 1; }
