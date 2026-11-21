# identity

Authentication and authorization service of the platform: an **OAuth 2.0 / OpenID Connect provider** that issues **JWTs** (with `jti`), keeps **RBAC** roles and permissions, supports **token exchange** (RFC 8693) with a per-service audience, an SSO session, **MFA (TOTP)** that each user can turn on or off (or an admin can enforce) and **password reset** by e-mail through `courier`.

Module: `github.com/huponx/identity`. Contracts live in `protos` (`identity/v1`), schema in `db-migration` (`identity_*`, `V1..V7`), shared code (`jwtx`, `authz`, `authn`, `grpcserver`, `tokenexchange`, `oidcclient`) in `gocommon`.

```
browser --OIDC--> gatekeeper (BFF) --OIDC code+PKCE--> identity (HTTP :8080)
                       |  token exchange (aud per service)
                       v
                   services (gRPC) --JWKS--> verify locally, check perms
admin tools / services --gRPC :9090 (IdentityService)--> identity
```

Every flow, with the code that handles each step, is described in [docs/flows.md](docs/flows.md).
How services authenticate to each other (ServiceAccount token, client credentials, token exchange, static token): [docs/service-to-service-auth.md](docs/service-to-service-auth.md).
What happens when a user calls an auth API or a normal API through the gatekeeper is in [docs/api-call-flow.md](docs/api-call-flow.md).

## Processes and ports

| Port | Protocol | What |
| --- | --- | --- |
| `8080` (`HTTP_PORT`) | HTTP | OAuth/OIDC endpoints, login/MFA/password pages, `/healthz`, `/readyz`. The only port an ingress exposes |
| `9090` (`PORT`) | gRPC | `identity.v1.IdentityService` (users, roles, clients, exchange policies, MFA admin, introspection). Callers present identity JWTs (`aud` = `identity`); each RPC needs a permission |

| HTTP endpoint | |
| --- | --- |
| `/.well-known/openid-configuration`, `/.well-known/jwks.json` | discovery and public keys |
| `GET /oauth2/authorize` | code flow, PKCE `S256` mandatory for every client, `prompt`, `max_age`, `acr_values=mfa` |
| `POST /oauth2/token` | grants `authorization_code`, `refresh_token` (rotation + reuse detection), `client_credentials`, `urn:ietf:params:oauth:grant-type:token-exchange` |
| `POST /oauth2/revoke`, `POST /oauth2/introspect`, `/userinfo` | RFC 7009, RFC 7662, OIDC |
| `/oauth2/logout` | RP-initiated logout and back-channel logout to the clients |
| `/login`, `/login/mfa`, `/password/forgot`, `/password/reset`, `/account/mfa` | pages (CSRF token, `__Host-` cookies, security headers) |

## Tokens

Access tokens are JWTs signed with ES256/RS256 (`kid` in the JWKS), `aud` = the service they are for, claims `sub`, `jti`, `scope`, `roles`, `perms`, `client_id`, `amr`, `acr`, `sid`; exchanged tokens add `act` (who acts for the user). Services verify them **locally** with the JWKS (`gocommon/jwtx`) and use `introspect` only for immediate revocation checks.

Permissions are colon separated segments with segment wildcards: `*` alone matches everything, a middle `*` matches one segment, a trailing `*` one or more (`identity:*:read`, `courier:notification:send`). Roles: `admin` (`*`) and `viewer` are seeded.

**Token exchange** is deny by default: it needs a row in `identity_exchange_policies` `(client, audience)`; the subject token must be a live access token whose audience is the caller's `resource`; scope can only narrow; permissions are re-read from the database and filtered by audience; the result lives 2 minutes, has no refresh token and carries the caller in `act`.

## Configuration

| Variable | Default | |
| --- | --- | --- |
| `IDENTITY_ISSUER` | required | public URL (`https://auth.example.com`); must be `https` outside `ENV=local` |
| `IDENTITY_SIGNING_KEY_FILE` / `IDENTITY_SIGNING_KEY_ID` | required | PEM private key (EC P-256 or RSA 2048+) and its `kid` |
| `IDENTITY_PREVIOUS_KEYS_DIR` | empty | retired keys (`<kid>.pem`) kept in the JWKS after a rotation |
| `IDENTITY_ACCESS_TOKEN_TTL` / `_ID_TOKEN_TTL` / `_REFRESH_TOKEN_TTL` / `_EXCHANGE_TOKEN_TTL` | `10m` / `10m` / `720h` / `2m` | |
| `IDENTITY_SESSION_IDLE_TTL` / `_ABSOLUTE_TTL` | `8h` / `168h` | SSO session |
| `IDENTITY_MFA_MODE` | `optional` | `off`, `optional` (each user chooses) or `required` (everyone) |
| `IDENTITY_MFA_KEY` | required unless `off` | `id:base64(32 bytes)`, comma separated; the first seals TOTP secrets (AES-GCM), the others only open (rotation) |
| `IDENTITY_MFA_ISSUER_NAME` | `Example` | label in authenticator apps |
| `IDENTITY_AUTH_AUDIENCE` | `identity` | `aud` accepted by the gRPC API |
| `IDENTITY_TRUSTED_PROXIES` | empty | CIDRs of the ingress, for the client IP of the rate limits |
| `COURIER_TARGET`, `COURIER_TOKEN_FILE` | empty | e-mails; empty disables them (links are logged when `ENV=local`) |
| `POSTGRES_*`, `REDIS_*`, `HOST`, `ENV`, `LOG_*` | | gocommon blocks |

MFA per user: with `optional` a user turns it on/off in `/account/mfa` (disabling asks for the password and a code); an admin can enforce, un-enforce, disable or reset it per user (`identityctl user mfa`, or `SetUserMFA`/`EnforceUserMFA`/`ResetUserMFA` over gRPC). Recovery codes are shown once.

## CI/CD

`.github/config/ci.yaml` is the contract and `.github/workflows/{pr,main,staging,production}.yml` call the reusable workflows of `huponx/actions` (`service-*.yml`). Same flows as courier:

| Flow | Trigger | Result |
|---|---|---|
| pr | pull request to `main` or `release*` | lint, test, build, Trivy scan, `helm lint`; nothing pushed |
| main | push to `main` | image and chart pushed, deployment PR for `dev` in `mm-deploy` (automerge) |
| staging | push to `release*` | pre-release `v<YYYY>.<MM>.N-release-<sha7>`, image and chart pushed, deployment PR for `staging` |
| production | release published | no build; verifies the image and chart of the release tag exist, deployment PR for `production` |

Required secret: `BOT_TOKEN` (write access to `mm-deploy`), or a GitHub App (`DEPLOY_APP_ID` variable and `DEPLOY_APP_PRIVATE_KEY` secret).

## Repository setup (one time, GitHub)

Do this once per repository, before the first release. Commands use the [GitHub CLI](https://cli.github.com) (`gh auth login` first, with admin rights on the repositories). `REPO=huponx/identity`.

1. **`huponx/actions` is published**: a release exists and the floating `v1` tag points to it (the workflows use `huponx/actions/...@v1`):

   ```bash
   gh release list -R huponx/actions --limit 3
   gh api repos/huponx/actions/git/ref/tags/v1 --jq .object.sha
   # private repo only: share the actions with the other repositories of the owner
   gh api -X PUT repos/huponx/actions/actions/permissions/access -f access_level=user
   ```

2. **Token for `mm-deploy`**: `GITHUB_TOKEN` cannot open PRs in another repository. Pick one:

   ```bash
   # a) PAT (fine-grained, repository huponx/mm-deploy: Contents and Pull requests write)
   gh secret set BOT_TOKEN -R huponx/identity                       # paste the token

   # b) GitHub App installed on mm-deploy (Contents and Pull requests write)
   gh variable set DEPLOY_APP_ID -R huponx/identity --body "<app id>"
   gh secret set DEPLOY_APP_PRIVATE_KEY -R huponx/identity < app-private-key.pem
   ```

   The App takes precedence when `DEPLOY_APP_ID` is set; without it `BOT_TOKEN` is used.

3. **Optional**: Slack notification of deployment PRs (set `slack-channel` in `ci.yaml`): `gh secret set SLACK_WEBHOOK_URL -R huponx/identity`.

4. **Workflow permissions** (packages and the staging pre-release need write):

   ```bash
   gh api -X PUT repos/huponx/identity/actions/permissions/workflow \
     -f default_workflow_permissions=write -F can_approve_pull_request_reviews=false
   ```

5. **GHCR packages**: after the first `main` run the packages `identity` and `charts/identity` exist. Link each to the repository (package settings, "Manage Actions access", role Write) and give the ArgoCD clusters pull access (public, or an image pull secret and an OCI repository credential in each ArgoCD). `go-application` must be readable from `oci://ghcr.io/huponx/charts`.

   ```bash
   gh api "/user/packages?package_type=container" --jq '.[].name'
   ```

6. **Branch rulesets**. Merge the workflows to `main` first, while `main` is unprotected: status checks only show up in the ruleset picker after they have run once. Save the files below as `main-ruleset.json` and `release-ruleset.json` (inputs only, do not commit them) and apply:

   `main-ruleset.json` (PR required, squash only, required checks of the `pr` flow, no force push or deletion):

   ```json
   {
     "name": "protect main",
     "target": "branch",
     "enforcement": "active",
     "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
     "rules": [
       { "type": "deletion" },
       { "type": "non_fast_forward" },
       { "type": "pull_request", "parameters": {
           "required_approving_review_count": 0, "dismiss_stale_reviews_on_push": false,
           "require_code_owner_review": false, "require_last_push_approval": false,
           "required_review_thread_resolution": false,
           "allowed_merge_methods": ["squash"] } },
       { "type": "required_status_checks", "parameters": {
           "strict_required_status_checks_policy": true,
           "required_status_checks": [
             { "context": "pr / contract" },
             { "context": "pr / lint-test" },
             { "context": "pr / build / build (identity)" } ] } }
     ],
     "bypass_actors": []
   }
   ```

   `release-ruleset.json` (a merge into `release*` creates a staging pre-release, so it needs a PR with the same checks, and no force push or deletion):

   ```json
   {
     "name": "protect release branches",
     "target": "branch",
     "enforcement": "active",
     "conditions": { "ref_name": { "include": ["refs/heads/release*"], "exclude": [] } },
     "rules": [
       { "type": "deletion" },
       { "type": "non_fast_forward" },
       { "type": "pull_request", "parameters": {
           "required_approving_review_count": 0, "dismiss_stale_reviews_on_push": false,
           "require_code_owner_review": false, "require_last_push_approval": false,
           "required_review_thread_resolution": false,
           "allowed_merge_methods": ["merge", "squash"] } },
       { "type": "required_status_checks", "parameters": {
           "strict_required_status_checks_policy": false,
           "required_status_checks": [
             { "context": "pr / contract" },
             { "context": "pr / lint-test" },
             { "context": "pr / build / build (identity)" } ] } }
     ],
     "bypass_actors": []
   }
   ```

   ```bash
   REPO=huponx/identity
   gh api repos/$REPO/rulesets --method POST --input main-ruleset.json
   gh api repos/$REPO/rulesets --method POST --input release-ruleset.json
   gh api repos/$REPO/rulesets --jq '.[] | {id, name, enforcement}'   # verify
   ```

   The check names are `<caller job> / <reusable job>`: confirm them with `gh pr checks <pr>` after the first PR run (they are the same as courier's, with `build (identity)` for the single image). To change a ruleset later: `gh api repos/$REPO/rulesets/<id> --method PUT --input main-ruleset.json`. The release ruleset applies to every `release*` branch, so create the first one (for example `release`) from `main` before applying it. Rulesets on a private repo need a paid GitHub plan.

7. **`mm-deploy`** (once for all services; skip if already done):

   ```bash
   gh repo edit huponx/mm-deploy --enable-auto-merge --delete-branch-on-merge
   gh label create automerge -R huponx/mm-deploy --color 0E8A16 --description "Merge automatically when checks pass" || true
   ```

   Required checks on `mm-deploy` `main`: `ci`, `diff`, `cve`, `pr-title`. After the first publish add `applications/<env>/identity.yaml` (already in the repository) with `targetRevision` set to the published version; later versions come from the deployment PRs.

8. **Verify**:

   ```bash
   gh secret list -R huponx/identity && gh variable list -R huponx/identity
   gh run list -R huponx/identity --workflow main.yml --limit 1      # after merging a PR into main
   gh pr list -R huponx/mm-deploy --label automerge                  # the dev deployment PR
   ```

## Setup (one time)

Runtime setup of the service in the cluster (after the repository setup above):

1. **Schema**: apply `db-migration` (`V1..V7`) to the `identity` database.
2. **Secrets** (signing key, MFA key, passwords) are created by `mm-ansible` from its vault, never by hand and never in git (the `mm-deploy` policy forbids secrets there). Generate the values once and store them in the vault, see the mm-ansible README, "Identity and gatekeeper secrets":
   ```bash
   cd ../mm-ansible
   make identity-secrets                      # signing key (EC P-256), MFA key and gatekeeper session key; copied to the clipboard
   make vault-edit F=k8s_secrets_vault.yml    # paste under vault_k8s_secrets:
   make deploy TAGS=secrets                   # creates identity-signing-key, identity-mfa-key, ... in the namespace application
   ```
   The chart mounts `identity-signing-key` read-only (mode `0400`) at `/var/run/identity/keys/` and sets `IDENTITY_SIGNING_KEY_FILE=/var/run/identity/keys/signing.pem`; the key id (any short string, it goes in the `kid` header and the JWKS) is `IDENTITY_SIGNING_KEY_ID` in the Application values of `mm-deploy`. Every replica mounts the same key. The pod reads the key at start (the `reloader` restarts it when the Secret changes).

   **Rotation:** (a) in the vault keep the old PEM as the Secret `identity-previous-keys` with the key `<old kid>.pem` (add that Secret to mm-ansible `k8s_secrets.yml`; the chart mounts it, optional, at `/var/run/identity/previous-keys`, `IDENTITY_PREVIOUS_KEYS_DIR`), (b) replace `signing.pem` with a new key (`make identity-secrets` prints one) and set a new `IDENTITY_SIGNING_KEY_ID` in `mm-deploy`, (c) `make deploy TAGS=secrets`; the pods restart. New tokens are signed with the new key; old tokens keep verifying because the old public key stays in the JWKS (services refresh their JWKS cache on an unknown `kid`). Delete the previous key after the longest token lifetime (refresh tokens are opaque, so the access/ID token TTL, 10 minutes by default, is enough). MFA key (`identity-mfa-key`, key `keys`): to rotate, prepend a new `k2:<key>,k1:<key>` (the first seals, the others only open).
3. Other Secrets referenced by `application.secrets`: Postgres password (`postgres-data-rw-credentials`) and Redis password (`redis-local-credentials`), also from the mm-ansible vault.
4. **Deploy** with `mm-deploy` (`applications/<env>/identity.yaml`): set `IDENTITY_ISSUER`, `IDENTITY_SIGNING_KEY_ID`, `POSTGRES_HOST`, `REDIS_HOST`, the ingress host/TLS, and allow identity's ServiceAccount in courier (`COURIER_AUTH_ALLOWED`).
5. **First admin** (only works while no admin exists), see [Running identityctl](#running-identityctl-in-kubernetes):
   ```bash
   kubectl -n application exec -it deploy/identity -- \
     env IDENTITY_BOOTSTRAP_PASSWORD='<strong password>' /identityctl bootstrap --email admin@example.com
   ```
6. **Clients and policies** (`identityctl client create ...`, `identityctl exchange set ...`; see `identityctl` without arguments). For a web app behind gatekeeper see the gatekeeper README.
   The client secret that `client create` prints once goes into the mm-ansible vault (`application-gatekeeper-client.secret`, then `make deploy TAGS=secrets`), not into a log or a shell history.

### Running identityctl in Kubernetes

The image ships `/identityctl` next to `/identity`. `identityctl` talks straight to Postgres and Redis and reads the same environment as the server (`POSTGRES_*`, `REDIS_*`, `IDENTITY_*`), which the identity pod already has, so the simplest way is to run it inside that pod:

```bash
# first admin (the password is read from the environment of this command only)
kubectl -n application exec -it deploy/identity -- \
  env IDENTITY_BOOTSTRAP_PASSWORD='<strong password>' /identityctl bootstrap --email admin@company.com

# the client of the gateway, its exchange policy, and the origin of another web app
kubectl -n application exec -it deploy/identity -- /identityctl client create --id gatekeeper --type confidential --resource gatekeeper \
  --redirect-uri https://api.company.com/auth/callback --post-logout-uri https://admin.company.com/ \
  --grant authorization_code --grant refresh_token --grant client_credentials \
  --grant urn:ietf:params:oauth:grant-type:token-exchange
kubectl -n application exec -it deploy/identity -- /identityctl exchange set --client gatekeeper --audience identity --depth 1
kubectl -n application exec -it deploy/identity -- /identityctl client add-uri --id gatekeeper --post-logout-uri https://dict.company.com/
```

- The image is distroless: there is no shell, call `/identityctl` directly (it is not in `PATH`).
- `client create` prints the client secret once. Put it straight into the vault of `mm-ansible` (Secret `gatekeeper-client`, key `secret`), not into a log or a shell history.
- The bootstrap password must satisfy the password policy (at least 12 characters, not the e-mail). Never commit it or put it in a ConfigMap; use a real value, not the sample of the local guide.
- Alternatives: port-forward Postgres and Redis and run a local `identityctl` with `POSTGRES_*`/`REDIS_*` pointing at them (it also needs the same `IDENTITY_MFA_KEY`), or a one-off Job on the identity image with `command: ["/identityctl", ...]` and the password from a Secret.
- The schema (`db-migration`) must be applied first. After the first admin exists, day to day administration goes through the admin web app or the gRPC API; keep `identityctl` for the bootstrap and emergencies.

## Local development

```bash
(cd ../db-migration && make up)            # Postgres + Redis + schema V1..V7 (db=app, user=postgres)
cp .env.example .env                       # ENV=local, local key, MFA key
make test                                  # unit tests
POSTGRES_PASSWORD=postgres make e2e             # code+PKCE, refresh reuse, client_credentials, token exchange, revoke
```

`scripts/e2e.sh` builds both binaries and runs `scripts/e2e.py` against a local Postgres/Redis (it creates its own clients; it creates an admin only when none exists).

`go.work` (git-ignored) points at `../gocommon` and the generated `protogen/go`; after both are released run `go get github.com/huponx/gocommon@latest github.com/huponx/protogen/go@latest && go mod tidy`.

## Security notes

PKCE `S256` is required for every client; redirect URIs are matched exactly; authorization codes are single use (`GETDEL`); refresh tokens rotate and a reused one revokes its whole family; passwords are argon2id with policy and rate limits, login does not reveal whether an account exists; client secrets are random (hex SHA-256 stored); TOTP secrets are AES-GCM sealed with the user id as AAD and a code cannot be replayed; password reset tokens are 256-bit, hashed, single use, 30 minutes; changing a password or resetting MFA ends the user's sessions and revokes issued access (per-user cutoff + `jti` denylist).
