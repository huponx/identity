#!/usr/bin/env bash
# Local end to end run: builds identity, creates an admin (when none exists) and two clients with
# random ids, starts the server and runs scripts/e2e.py against it. Safe to repeat.
#
# Needs a Postgres with the identity schema (db-migration V1..V7) and a Redis; point at them with
# POSTGRES_* and REDIS_* (defaults of gocommon otherwise).
set -euo pipefail
cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'kill "${pid:-0}" 2>/dev/null || true; rm -rf "$tmp"' EXIT

export ENV=local HTTP_PORT=${HTTP_PORT:-18080} PORT=${PORT:-19090}
export IDENTITY_ISSUER=http://localhost:$HTTP_PORT
export IDENTITY_SIGNING_KEY_FILE=$tmp/k1.pem IDENTITY_SIGNING_KEY_ID=k1
export IDENTITY_MFA_KEY="k1:$(openssl rand -base64 32)"
export IDENTITY_BOOTSTRAP_PASSWORD='Correct-Horse-Battery-9'
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/k1.pem" 2>/dev/null

go build -o "$tmp/identity" ./cmd/identity
go build -o "$tmp/identityctl" ./cmd/identityctl

"$tmp/identityctl" bootstrap --email admin@example.com || echo "(bootstrap skipped: an admin exists; its password must be the one above)"
suf=$(openssl rand -hex 3); export WEB_CLIENT=webgk-$suf GK_CLIENT=gk-$suf
"$tmp/identityctl" client create --id "$WEB_CLIENT" --type public --resource gatekeeper --redirect-uri http://localhost:3000/cb
secret=$("$tmp/identityctl" client create --id "$GK_CLIENT" --type confidential --resource gatekeeper \
  --grant client_credentials --grant urn:ietf:params:oauth:grant-type:token-exchange --role admin | sed -n 's/^client secret (shown once): //p')
"$tmp/identityctl" exchange set --client "$GK_CLIENT" --audience courier --depth 1

"$tmp/identity" >"$tmp/identity.log" 2>&1 &
pid=$!
for _ in $(seq 1 50); do curl -fs "$IDENTITY_ISSUER/healthz" >/dev/null && break; sleep 0.2; done

ISSUER=$IDENTITY_ISSUER EMAIL=admin@example.com PASSWORD=$IDENTITY_BOOTSTRAP_PASSWORD GATEKEEPER_SECRET=$secret \
  python3 scripts/e2e.py || { tail -30 "$tmp/identity.log"; exit 1; }
