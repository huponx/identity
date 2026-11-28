# identity

Authentication and authorization service of the platform: an **OAuth 2.0 / OpenID Connect provider** that issues **JWTs** (with `jti`), keeps **RBAC** roles and permissions, supports **token exchange** (RFC 8693) with a per-service audience, an SSO session, **MFA (TOTP)** that each user can turn on or off (or an admin can enforce) and **password reset** by e-mail through `courier`.

Module: `github.com/huponx/identity`. Contracts live in `protos` (`identity/v1`), schema in `db-migration` (`identity_*`, `V1..V8`), shared code (`jwtx`, `authz`, `authn`, `grpcserver`, `tokenexchange`, `oidcclient`) in `gocommon`.

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
| `/login`, `/login/mfa`, `/password/forgot`, `/password/reset`, `/password/set`, `/account/mfa`, `/logout` | the sign in app (React, `web/apps/auth`, copied into the image at `/ui`, `IDENTITY_UI_DIR`) |
| `/auth-api/*` | JSON API of that app (CSRF token in the body, `__Host-` cookies, security headers) |

## Tokens

Access tokens are JWTs signed with ES256/RS256 (`kid` in the JWKS), `aud` = the service they are for, claims `sub`, `jti`, `scope`, `roles`, `perms`, `client_id`, `amr`, `acr`, `sid`; exchanged tokens add `act` (who acts for the user). Services verify them **locally** with the JWKS (`gocommon/jwtx`) and use `introspect` only for immediate revocation checks.

Permissions are colon separated segments with segment wildcards: `*` alone matches everything, a middle `*` matches one segment, a trailing `*` one or more (`identity:*:read`, `courier:notification:send`). Roles: `admin` (`*`) and `viewer` are seeded.

### Where permissions come from

Permissions are **defined by the services, in code**, not by administrators (the admin app only reads them):

- Each service lists its permissions in one file, `protos/<service>/v1/permissions.proto`, and names them in the `authz.v1.rule` option of each RPC (`any_of`, `all_of` or `public`). Identity declares `identity:*` there; `bill:*` and `system:*` (no process of their own) are synced by identity from its copy of their files (`service.OwnPermissionFiles`).
- **At start identity saves its own file in the catalog** (`identity_permissions`: `service`, `description`, `retired_at`), one transaction per service, before it listens; a database error stops the start. Other services call `RegisterPermissions(service, permissions[])` at their start (service token, permission `identity:permission:register`, held by the role `service_registrar`; set `"roles":["service_registrar"]` on the client in `SETUP_CONFIG`). A service may only register names that start with `<service>:`, and only if its client's `resource` is that service. The service is not ready until it succeeded and exits after `PERMISSIONS_SYNC_TIMEOUT` (default 2m), so a rolling deploy halts on the new pods while the old ones keep serving the old set.
- A sync is a set diff per service: new -> insert; changed description -> update; `renamed_from` -> the role grants of the old name move to the new one and the old row goes; **gone from the code** -> deleted when no role holds it, else **retired** (`retired_at`). The role grants stay, a re-add or a rename restores them, a retired permission is left out of the `perms` of tokens and of the role editor, the role page lists it as "retired" and the grant can be removed there (`SetRolePermissions` accepts a retired name that the role already holds, never a new one). A retired permission that no role holds any more is deleted at the next sync. The sync never touches `identity_user_roles` or grants of wildcards, never retires the permissions of a service that did not report in, and logs every change.
- **Wildcards are not stored.** `ListPermissions` adds the ones that cover at least one declared permission (`wildcard: true`): `*`, `<service>:*`, `<service>:*:<action>`, `<service>:<resource>:*`. `SetRolePermissions` accepts a catalog permission or such a wildcard, else `unknown_permission`. A wildcard grant that no longer covers anything (its service left the code) is kept and shown as retired; it matches nothing. `*` is always valid.
- Rows nobody owns (created by an administrator before this, `service = ''`) go through the same rule at the first start.

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
| `IDENTITY_MFA_ISSUER_NAME` | `Example` | label in authenticator apps, and the name next to the logo in every e-mail |
| `IDENTITY_AUTH_AUDIENCE` | `identity` | `aud` accepted by the gRPC API |
| `IDENTITY_TRUSTED_PROXIES` | empty | CIDRs of the ingress, for the client IP of the rate limits |
| `IDENTITY_PORTAL_URL` | required | the portal (https; http only with `ENV=local`): where a user lands after signing in at identity itself (no `return_to`), and where `/` sends a signed in user |
| `IDENTITY_REGISTRATION_ENABLED` | `false` | opens `POST /auth-api/register` (self-registration, the "Create an account" link of the sign in page); off, the endpoint answers 404. No CAPTCHA: only the rate limit per client IP (10/hour) and per e-mail (3/hour). What happens after a request is the system setting **registration requires approval** (Admin → System settings, default **on**): see below |
| `IDENTITY_RATE_LIMIT_FACTOR` | `1` | multiplies the maximum of every rate limit (login, registration, password reset, MFA); above 1 only with `ENV=local` (`scripts/local.sh` sets 100), otherwise the service does not start |
| `IDENTITY_ADMIN_URL` | empty | the admin app (https; http only with `ENV=local`): the "new registration" mail to the users who may approve links to `{IDENTITY_ADMIN_URL}/users/{id}` of the applicant; empty omits the link |
| `IDENTITY_WEBAUTHN_ENABLED` | `true` | passkeys (WebAuthn): a way to sign in next to the password, and a second factor. Off, the passkey endpoints answer 404 and the pages hide them |
| `IDENTITY_WEBAUTHN_RP_ID` | host of `IDENTITY_ISSUER` | the relying party id: the host, or a parent domain, of every origin below. **It is bound into every passkey: changing it later makes all of them unusable.** Choose the registrable domain the issuer, the portal and the admin app share (`momofamily.top` for `auth.momofamily.top`, `momofamily.top`, `admin.momofamily.top`) before the first passkey is made, and keep it. `localhost` locally |
| `IDENTITY_WEBAUTHN_RP_NAME` | `IDENTITY_MFA_ISSUER_NAME` | the name the authenticator shows |
| `IDENTITY_WEBAUTHN_ORIGINS` | the issuer, portal and admin origins that the RP ID covers | origins (`https://host`, no path; http only with `ENV=local`) allowed to run a ceremony; the portal runs it too, through the gateway. The service refuses to start when the RP ID is not the host or a parent domain of one of them. With the default RP ID (the issuer host) the portal and admin origins are left out: set the RP ID to the shared parent domain to use passkeys there |
| `IDENTITY_REGISTRATION_ROLE` | `member` | role of a self-registered account (migration V36 creates it with the dictionary permissions) |
| `IDENTITY_UI_DIR` | `/ui` | build of the sign in app (`web/apps/auth`; the image carries it). Required unless `ENV=local`, where the page paths answer 503 without it |
| `COURIER_TARGET`, `COURIER_TOKEN_FILE` | empty | e-mails; empty disables them (links are logged when `ENV=local`) |
| `COURIER_INSECURE` | `true` | plaintext gRPC to courier; `false` once courier serves TLS (CA: `GRPC_TLS_CA_FILE`) |
| `GRPC_TLS_CERT_FILE`, `GRPC_TLS_KEY_FILE` | empty | serve the gRPC API (9090) over TLS, reloaded when the files change (cert-manager); clients of identity must then use `*_INSECURE=false` |
| `POSTGRES_*`, `REDIS_*`, `HOST`, `ENV`, `LOG_*` | | gocommon blocks |

MFA per user: with `optional` a user turns it on/off in `/account/mfa` (disabling asks for the password and a code); an admin can enforce, un-enforce, disable or reset it per user (in the admin app, or `SetUserMFA`/`EnforceUserMFA`/`ResetUserMFA` over gRPC). Recovery codes are shown once.

## Passkeys

A passkey (WebAuthn credential) is a second way to sign in, next to the password. It is usernameless (a discoverable
credential: the browser lists the passkeys, no e-mail is typed), always asks for user verification (biometric or PIN) and
takes no attestation. Because of the user verification a passkey login counts as multi-factor: the session gets
`amr` `["swk","mfa"]` (synced, backup eligible key) or `["hwk","mfa"]` (device bound), `acr=mfa` appears in the tokens, and it
satisfies mode `required`, a user's enforcement and `acr_values=mfa` without a TOTP step. A user who signs in with the
password stays a password sign in: a passkey is not asked for after it, unless MFA is required (mode `required` or the
user is enforced), when it is the second factor (a user with a passkey and no TOTP is then asked for it, not sent to
enroll). A TOTP device is always asked for. A client that asks for `acr_values=mfa` gets the passkey step for a password
session of a user who has one.

- **The RP ID cannot change.** It is bound into every passkey (`IDENTITY_WEBAUTHN_RP_ID`, see Configuration): set it to the
  domain the issuer, the portal and the admin app share before the first passkey is made.
- Table `identity_user_passkeys` (migration V39). The WebAuthn user handle is the user id (opaque). The public key is stored
  as it is (no sealing, unlike the TOTP secret). A sign count that does not move forward is refused and logged.
- The ceremony state lives in Redis (`identity:wa:*`, 5 minutes, **single use**), tagged with its purpose (`login`, `mfa`,
  `register`): an answer to the options of another purpose is refused.
- Adding or deleting a passkey needs the **current password** (a stolen session cannot add a key) and sends the user a mail
  (the `identity_mfa_changed` template with `passkey_added` / `passkey_removed`). The administrator's "Reset MFA"
  (`ResetUserMFA`) removes the passkeys too; turning TOTP off does not.
- Rate limits (`state.Allow`): 60 begin/finish per client IP per 5 minutes, 10 failures per user per 10 minutes, the password
  of an add/delete 5 per 15 minutes; the second factor shares the `mfa:user:` limiter and the 5 tries per challenge.
- gRPC for the portal: `ListMyPasskeys`, `BeginMyPasskey`, `FinishMyPasskey`, `RenameMyPasskey`, `DeleteMyPasskey` (`public`
  rules like the other `*My*` RPCs, routes `/api/me/passkeys` in the gateway); `GetUserMFA` returns `passkey_count`.
- Tests: `internal/passkey` runs the ceremonies with a software authenticator (`passkeytest`); `internal/oauth/passkey_test.go`
  runs the whole server on PostgreSQL and Redis (`IDENTITY_TEST_POSTGRES_URL` and `IDENTITY_TEST_REDIS_URL`).

## Active sessions

Every sign in (password, password + code, passkey, enrollment) creates one SSO session in Redis, so a user who signs in on
three browsers has three. Besides the user, the methods (`amr`) and the times, a session keeps what identifies the device:
the **IP** (`c.ClientIP()`, which honours `IDENTITY_TRUSTED_PROXIES`), the **User-Agent** (cut to 512 bytes) and a **last
seen** time, written at most once a minute (on a read of the session, with its idle expiry kept). The browser, OS and
kind of device are parsed from the User-Agent when the list is read (`internal/useragent`, a small rule table), so a
better table also describes the sessions that exist. Nothing else is stored: no login history, no location, and everything
goes with the session (idle `IDENTITY_SESSION_IDLE_TTL`, absolute `IDENTITY_SESSION_ABSOLUTE_TTL`, or when it is ended). A session
created before this existed shows as "Unknown device".

The API (all non-breaking): the signed-in user sees and ends **their own** sessions (`ListMySessions`, `RevokeMySession`,
`RevokeMyOtherSessions`; gateway `GET /api/me/sessions`, `DELETE /api/me/sessions/{id}`, `POST /api/me/sessions/revoke-others`;
`current` is the session whose `sid` is in the caller's token; another user's or an unknown id is NOT_FOUND
`session_not_found`; ending the current one is a sign out). An administrator with `identity:user:read` lists the sessions
of a user (`ListUserSessions`, `GET /api/users/{user_id}/sessions`) and with `identity:user:write` ends all of them
(`RevokeUserSessions`, `DELETE /api/users/{user_id}/sessions`, the same as disabling the user without disabling: every
session, every refresh token and the access token cutoff). There is no revoke of a single session of another user.

Ending a session deletes it, revokes its refresh tokens and sends back-channel logout to the clients that used it, so the
portal and admin (gatekeeper) sessions of that browser end too. **Access tokens already issued are not recalled**: where a
service verifies them locally they work until they expire (`IDENTITY_ACCESS_TOKEN_TTL`, 10 minutes by default);
introspection and token exchange refuse them only after "sign out of all sessions" of an administrator (the cutoff).

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

1. **Schema**: apply `db-migration` (`V1..V8`) to the `identity` database.
2. **Secrets** (signing key, MFA key, passwords) are created by `mm-ansible` from its vault, never by hand and never in git (the `mm-deploy` policy forbids secrets there). Generate the values once and store them in the vault, see the mm-ansible README, "Identity and gatekeeper secrets":
   ```bash
   cd ../mm-ansible
   make identity-secrets                      # signing key (EC P-256), MFA key and gatekeeper session key; copied to the clipboard
   make vault-edit F=k8s_secrets_vault.yml    # paste under vault_k8s_secrets:
   make deploy TAGS=secrets                   # creates identity-signing-key, identity-mfa-key, ... in the namespace application
   ```
   The chart mounts `identity-signing-key` read-only (mode `0440`, group `fsGroup: 65532`, the pod runs as the distroless `nonroot` user 65532) at `/var/run/identity/keys/` and sets `IDENTITY_SIGNING_KEY_FILE=/var/run/identity/keys/signing.pem`; the key id (any short string, it goes in the `kid` header and the JWKS) is `IDENTITY_SIGNING_KEY_ID` in the Application values of `mm-deploy`. Every replica mounts the same key. The pod reads the key at start (the `reloader` restarts it when the Secret changes).

   **Rotation:** (a) in the vault keep the old PEM as the Secret `identity-previous-keys` with the key `<old kid>.pem` (add that Secret to mm-ansible `k8s_secrets.yml`; the chart mounts it, optional, at `/var/run/identity/previous-keys`, `IDENTITY_PREVIOUS_KEYS_DIR`), (b) replace `signing.pem` with a new key (`make identity-secrets` prints one) and set a new `IDENTITY_SIGNING_KEY_ID` in `mm-deploy`, (c) `make deploy TAGS=secrets`; the pods restart. New tokens are signed with the new key; old tokens keep verifying because the old public key stays in the JWKS (services refresh their JWKS cache on an unknown `kid`). Delete the previous key after the longest token lifetime (refresh tokens are opaque, so the access/ID token TTL, 10 minutes by default, is enough). MFA key (`identity-mfa-key`, key `keys`): to rotate, prepend a new `k2:<key>,k1:<key>` (the first seals, the others only open).
3. Other Secrets referenced by `application.secrets`: Postgres password (`postgres-data-rw-credentials`) and Redis password (`redis-local-credentials`), also from the mm-ansible vault.
4. **Deploy** with `mm-deploy` (`applications/<env>/identity.yaml`): set `IDENTITY_ISSUER`, `IDENTITY_SIGNING_KEY_ID`, `POSTGRES_HOST`, `REDIS_HOST`, the ingress host/TLS, and allow identity's ServiceAccount in courier (`COURIER_AUTH_ALLOWED`).
5. **Initial setup Job** (first admin, the client of the gateway, its exchange policy), see [Initial setup Job](#initial-setup-job). It runs once as an ArgoCD hook from the same `mm-deploy` Application, then you remove it.
6. Everything else (more users, roles and permissions, later clients, MFA, password resets) is done in the admin web app or over the gRPC API. There is no CLI.

### Initial setup Job

`/identity-setup` (in the identity image, `cmd/identity-setup`) is run once as a Kubernetes Job (the `setup` alias of the `go-job` chart, an ArgoCD `PostSync` hook). It needs only Postgres (the schema from `db-migration` must exist) and does only what the UI and the gRPC API cannot do from nothing:

| Step | Behaviour |
|---|---|
| First admin | Created **only when no admin exists** (checked and inserted in one transaction under an advisory lock). Any later run, with the same or another e-mail, skips it. The password comes from the Secret `identity-admin` (`SETUP_ADMIN_PASSWORD`, set by mm-ansible, see "Identity and gatekeeper secrets") and must pass the password policy. The user is created with `must_change_password`: at the first sign in identity asks for a new password (`/login/password`) before any session, MFA step or authorization code. |
| Clients | Declared in `SETUP_CONFIG`. Created when missing; when present the redirect and post logout URIs, grants and scopes are **added** (never removed) and missing roles assigned. A confidential client takes its secret from an environment variable named by `secret_env` (the Secret `gatekeeper-client`); the hash is stored on create and whenever the Secret changes. Nothing is printed. Type and `resource` of an existing client cannot change (the Job fails); `backchannel_logout_uri` is only used on create. |
| Exchange policies | Upserted from `SETUP_CONFIG`. |

Everything except the admin is idempotent, so a re-sync before you remove the Job is harmless.

`SETUP_CONFIG` (JSON, unknown fields are rejected; an example lives in each `mm-deploy` `applications/<env>/identity.yaml`):

```json
{
  "admin": {"email": "admin@company.com", "name": "Administrator"},
  "clients": [{
    "id": "gatekeeper", "type": "confidential", "resource": "gatekeeper", "secret_env": "GATEKEEPER_CLIENT_SECRET",
    "redirect_uris": ["https://api.company.com/auth/callback"],
    "post_logout_uris": ["https://admin.company.com/", "https://dict.company.com/"],
    "grants": ["authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"]
  }],
  "exchange_policies": [{"client": "gatekeeper", "audience": "identity", "max_depth": 1}]
}
```

Client fields: `id`, `type` (`public`|`confidential`), `resource` (audience), `secret_env` (confidential only), `name`, `redirect_uris`, `post_logout_uris`, `backchannel_logout_uri`, `grants` (default `authorization_code`, `refresh_token`), `scopes` (default `openid profile email offline_access`), `roles`. `admin.keep_password: true` skips the forced change and is only for local runs and the end to end scripts.

**Rollout**

1. Put `identity-admin` (temporary password) and `gatekeeper-client` in the mm-ansible vault and `make deploy TAGS=secrets` (`make identity-secrets` generates both).
2. Release `db-migration` (`V8` adds `must_change_password`), then the identity chart (it carries the Job and the image has `/identity-setup`).
3. In `mm-deploy` `applications/<env>/identity.yaml` the `setup:` block (`enabled: true`, `POSTGRES_*`, `SETUP_CONFIG`, the three Secret references) is already present; bump `targetRevision` to the new release. ArgoCD runs the Job after the sync (`kubectl -n application logs job/<release>-job-<tag>`; the log lines never contain a secret).
4. Sign in at the identity host with the admin e-mail and the temporary password, choose your own password.
5. **Remove the `setup:` block from the `mm-deploy` Application** (the Job is not needed again), then remove `identity-admin` from the vault and from `k8s_secrets.yml` (`state: absent` first, see the mm-ansible README).

**Later changes of the clients.** The admin app cannot add URIs to an existing client (identity has no update call). To add a web app origin as a post logout URI, put the `setup:` block back with the new URI (and the Secrets it references, `identity-admin` can be left out of `SETUP_CONFIG`: without `admin` the step is skipped) and sync; remove it again afterwards. To rotate the `gatekeeper` secret use the admin app (Clients, rotate) and put the new value in the vault, and do not leave the Job deployed meanwhile: it would reset the secret to the value of the Secret.

If the first admin is locked out, use the password reset mail. If every admin is gone, delete the user rows by hand and re-add the `setup:` block: the Job creates the admin again because no admin exists.

## Local development

```bash
(cd ../db-migration && make up)            # Postgres + Redis + schema V1..V8 (db=app, user=postgres)
cp .env.example .env                       # ENV=local, local key, MFA key
make test                                  # unit tests
POSTGRES_PASSWORD=postgres make e2e             # code+PKCE, refresh reuse, client_credentials, token exchange, revoke
```

`scripts/e2e.sh` builds `identity` and `identity-setup`, runs the setup (its own clients with random ids; an admin only when none exists, with `keep_password`) and runs `scripts/e2e.py` against a local Postgres/Redis.

`go.work` (git-ignored) points at `../gocommon` and the generated `protogen/go`; after both are released run `go get github.com/huponx/gocommon@latest github.com/huponx/protogen/go@latest && go mod tidy`.

## Security notes

PKCE `S256` is required for every client; redirect URIs are matched exactly; authorization codes are single use (`GETDEL`); refresh tokens rotate and a reused one revokes its whole family; passwords are argon2id with policy and rate limits, login does not reveal whether an account exists; client secrets are random (hex SHA-256 stored); TOTP secrets are AES-GCM sealed with the user id as AAD and a code cannot be replayed; password reset tokens are 256-bit, hashed, single use, 30 minutes; changing a password or resetting MFA ends the user's sessions and revokes issued access (per-user cutoff + `jti` denylist).
