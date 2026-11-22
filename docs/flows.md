# Identity flows

This document describes every flow of `identity` and names the code that handles each step.
Paths are relative to the `identity` folder, except section 10, which is about `../gatekeeper`. Functions are referenced by name (line numbers
change too often to be useful).

## 1. Map of the code

| Package | Role |
| --- | --- |
| `cmd/identity/main.go` | Wires everything: Postgres, Redis, keys, token service, account service, gRPC server and the HTTP server. Runs the hourly refresh token cleanup (`cleanup`). |
| `cmd/identity-setup/main.go` | Initial setup, run once as a Kubernetes Job (first admin, clients, exchange policies). Talks straight to Postgres (no gRPC, no Redis). |
| `internal/setup` | The setup logic: config parsing, admin only when none exists, client reconcile, exchange policies. |
| `internal/oauth` | HTTP side: discovery, authorize, login, MFA pages, token, revoke, introspect, userinfo, logout, password reset, account MFA page. |
| `internal/account` | Logic shared by the HTTP pages, the gRPC API: password login, MFA, password reset, revocation, back-channel logout. |
| `internal/token` | Signs access, ID and logout JWTs. Verifies our own tokens. Implements token exchange (RFC 8693). |
| `internal/service` | gRPC `IdentityService` (administration) and the permission of each RPC. |
| `internal/state` | Redis: SSO sessions, authorization codes, MFA challenges, token denylist, user cutoff, rate limits. |
| `internal/store` | Postgres: users, roles, clients, refresh tokens, MFA factors, reset tokens, exchange policies. |
| `internal/mfa` | TOTP (on top of `gocommon/otp`), recovery codes, AES-GCM sealing of the TOTP secret. |
| `internal/password` | argon2id hashing, password policy, random values, token digests. |
| `internal/keys` | Loads the signing key and the retired keys that stay in the JWKS. |
| `internal/notify` | E-mails through courier (`Courier`), or `Log` / `None` for local runs. |
| `internal/appconfig` | Environment variables (`IDENTITY_*`, `POSTGRES_*`, `REDIS_*`). |

Two listeners run in one process:

- HTTP (`HTTP_PORT`, default 8080): `oauth.Server.Routes` in `internal/oauth/server.go`.
- gRPC (`PORT`, default 9090): `service.Service` registered in `cmd/identity/main.go`.

### HTTP routes

| Route | Handler (`internal/oauth`) |
| --- | --- |
| `GET /.well-known/openid-configuration` | `discovery` (`authorize.go`) |
| `GET /.well-known/jwks.json` | `jwks` (`authorize.go`) |
| `GET /oauth2/authorize` | `authorize` (`authorize.go`) |
| `POST /oauth2/token` | `tokenEndpoint` (`tokens.go`) |
| `POST /oauth2/revoke` | `revoke` (`tokens.go`) |
| `POST /oauth2/introspect` | `introspect` (`tokens.go`) |
| `GET, POST /userinfo` | `userinfo` (`tokens.go`) |
| `GET, POST /oauth2/logout` | `endSession` (`pages.go`) |
| `GET, POST /login` | `loginForm`, `loginSubmit` (`authorize.go`) |
| `GET, POST /login/mfa` | `mfaForm`, `mfaSubmit` (`authorize.go`) |
| `GET, POST /login/password` | `passwordChangeForm`, `passwordChangeSubmit` (`pages.go`): forced change of a temporary password |
| `GET, POST /password/forgot` | `forgotForm`, `forgotSubmit` (`pages.go`) |
| `GET, POST /password/reset` | `resetForm`, `resetSubmit` (`pages.go`) |
| `GET, POST /account/mfa` | `accountMFA`, `accountMFAConfirm` (`pages.go`) |
| `POST /account/mfa/disable` | `accountMFADisable` (`pages.go`) |

Every response goes through `securityHeaders` (no-store, CSP, no referrer) and `limitBody`
(64 KiB) from `server.go`.

### What lives where

| Data | Store | Key or table |
| --- | --- | --- |
| SSO session | Redis | `identity:sess:<hash(cookie)>`, `identity:sidx:<public id>`, `identity:usess:<user id>` |
| Authorization code (60 s) | Redis | `identity:code:<hash(code)>` |
| MFA challenge (5 min) | Redis | `identity:mfa:<hash(id)>` |
| Revoked access token (`jti`) | Redis | `identity:deny:<jti>` |
| Per user token cutoff | Redis | `identity:cutoff:<user id>` |
| Rate limit counters | Redis | `identity:rl:<key>` |
| Users, roles, clients, permissions | Postgres | `store.User`, `store.Role`, `store.Client` |
| Refresh tokens (rotating, by family) | Postgres | `identity_refresh_tokens` |
| MFA factor and recovery codes | Postgres | `store.MFAFactor` |
| Password reset tokens | Postgres | `store.CreatePasswordReset` and related |
| Token exchange policies | Postgres | `identity_exchange_policies` |

Secrets are never stored in clear: cookies, codes, challenge ids and reset tokens are stored
as SHA-256 (`state.hash`, `password.Digest`), client secrets as SHA-256 (`oauth.HashSecret`),
passwords as argon2id (`password.Hash`), the TOTP secret sealed with AES-GCM (`mfa.Sealer`).

## 2. Startup

`cmd/identity/main.go`, function `main`:

1. `config.MustLoad[appconfig.Identity]` and `cfg.Validate`.
2. `store.New` (Postgres) and `state.New` (Redis).
3. `keys.Load`: reads `IDENTITY_SIGNING_KEY_FILE`, the `kid` from `IDENTITY_SIGNING_KEY_ID`, and
   every `*.pem` in `IDENTITY_PREVIOUS_KEYS_DIR` (retired keys stay in the JWKS so old tokens
   verify).
4. `mfa.NewSealer(cfg.MFAKeys)` unless `IDENTITY_MFA_MODE=off`.
5. `token.New`, `notify.Build`, `account.New`.
6. gRPC server with auth `JWTAuth` (our own JWT, audience `IDENTITY_AUTH_AUDIENCE`, default
   `identity`). A static `IDENTITY_S2S_TOKEN` is accepted only when the environment is local.
   Permissions per RPC come from `service.Permissions` (deny by default).
7. HTTP server: `/healthz`, `/readyz` (Postgres and Redis), then `oauth.Server.Routes`.
8. On shutdown: HTTP shutdown, gRPC stop, `acct.Drain` (waits for mails and back-channel logout).

## 3. One time setup (the setup Job)

Handled by `cmd/identity-setup/main.go` and `internal/setup/setup.go`, run once as an ArgoCD
`PostSync` hook Job (the `setup` alias of the `go-job` chart, enabled from `mm-deploy` and removed
after the first success). Nothing can call the gRPC API before an admin and a client exist, so the
Job writes to the database directly. It needs only Postgres. Input: `SETUP_CONFIG` (JSON),
`SETUP_ADMIN_PASSWORD` and one environment variable per confidential client (`secret_env`), all
from Secrets set by mm-ansible. `setup.Parse` validates the config (unknown fields, URIs with
`store.ValidURI`, a `secret_env` for every confidential client).

| Step | Function | What it does |
| --- | --- | --- |
| First admin | `runAdmin` | `password.Check` (policy), `password.Hash`, then `store.CreateFirstAdmin`: in one transaction under `pg_advisory_xact_lock` it counts the admins and inserts the user with role `admin` and `must_change_password = true` only when there is none. Another run, or another e-mail, finds an admin and skips. `admin.keep_password` (local only) leaves the flag off. |
| Client | `runClient` | Missing: `store.CreateClient` with the defaults (grants `authorization_code`, `refresh_token`; scopes `openid profile email offline_access`) and `oauth.HashSecret` of the secret from the environment. Present: type and `resource` must match; URIs, grants and scopes are merged (`store.SetClientConfig`), missing roles assigned (`store.AssignRole`), and the secret hash is replaced when it differs. |
| Exchange policy | `Run` | `store.SetExchangePolicy` (upsert). |

Everything except the admin is idempotent. Nothing is printed that is a secret.

```mermaid
flowchart TD
    A[Job starts: SETUP_CONFIG, Secrets] --> B{admin in config}
    B -->|yes| C{any admin exists}
    C -->|no| D[create admin, must_change_password]
    C -->|yes| E[skip admin]
    B -->|no| F[clients]
    D --> F
    E --> F
    F --> G[create or merge each client, set secret hash]
    G --> H[exchange policies upsert]
    H --> I[done: remove the setup block from mm-deploy]
```

What the Job does not do (use the admin app or the gRPC API): more users, roles and permissions, MFA,
password resets, rotating a client secret, later clients. The admin app cannot add URIs to an
existing client (no update call); to add one, put the `setup:` block back with the new URI.

## 4. Authorization code flow with PKCE (browser login)

This is the main flow. Applications (the gatekeeper, the admin app) send the browser to
`/oauth2/authorize` and later swap the code for tokens.

```mermaid
sequenceDiagram
    participant B as Browser
    participant I as identity HTTP
    participant R as Redis
    participant P as Postgres
    participant A as Application (gatekeeper)

    B->>I: GET /oauth2/authorize?client_id&redirect_uri&state&code_challenge...
    I->>P: ClientByID
    alt no valid SSO session
        I-->>B: 302 /login?return_to=/oauth2/authorize?...
        B->>I: POST /login (email, password, csrf)
        I->>P: UserByEmail, verify argon2id
        I->>R: rate limit, create session
        I-->>B: 302 return_to + Set-Cookie sid
        B->>I: GET /oauth2/authorize (again, now with session)
    end
    I->>R: SaveCode (60 s)
    I-->>B: 302 redirect_uri?code&state&iss
    B->>A: GET redirect_uri?code
    A->>I: POST /oauth2/token (code, code_verifier, client auth)
    I->>R: TakeCode (GETDEL)
    I->>P: UserByID, permissions, roles
    I-->>A: access_token, id_token, refresh_token
```

Decision flow inside `authorize` (what the browser sees):

```mermaid
flowchart TD
    A[GET /oauth2/authorize] --> B{client and redirect_uri registered?}
    B -- no --> E1[HTML error page, no redirect]
    B -- yes --> C{params valid? code, state, PKCE S256, scope, prompt, max_age}
    C -- no --> E2[302 redirect_uri?error=...]
    C -- yes --> D{valid session, not too old for max_age, no prompt=login?}
    D -- no --> P{prompt=none?}
    P -- yes --> E3[302 error=login_required]
    P -- no --> L[302 /login?return_to=authorize]
    D -- yes --> M{second factor needed and session has no otp?}
    M -- no --> K[SaveCode 60 s, 302 redirect_uri?code&state&iss]
    M -- yes --> N{prompt=none?}
    N -- yes --> E4[302 error=interaction_required]
    N -- no --> O{user has MFA?}
    O -- yes --> Q[SaveChallenge, 302 /login/mfa]
    O -- no --> R[302 /account/mfa enrollment]
```

### 4.1 `GET /oauth2/authorize` — `Server.authorize` (`internal/oauth/authorize.go`)

Steps in the function, in order:

1. **Client and redirect URI.** `store.ClientByID`, then `contains(client.RedirectURIs, redirect_uri)`.
   Until both are trusted, errors are shown as an HTML page (`errorPage`), never redirected, so
   identity is not an open redirector.
2. **Parameters.** Checked here, errors go back to the client with `redirectErr`:
   - `response_type=code` only, the client must allow grant `authorization_code`.
   - `state` is required.
   - PKCE is required: `code_challenge_method=S256`, challenge 43 to 128 characters.
   - Every `scope` must be in `client.AllowedScopes` (default `openid`).
   - `prompt` may be `none` or `login`. `max_age` must be a number.
   - `acr_values=mfa` is refused when `MFAMode` is `off`.
3. **Who is signing in.** `sessionFrom` reads the `sid` cookie, `state.GetSession` (slides the idle
   expiry, enforces the absolute one), then `store.UserByID`. A disabled or deleted user ends the
   session. The user must log in when there is no session, `prompt=login`, or the session is
   older than `max_age`. With `prompt=none` this returns `login_required`. Otherwise the
   browser goes to `/login?return_to=...` (the `prompt` is removed so there is no loop).
4. **Second factor.** `account.MFARequirement(user)` and the session `amr`. If a code is
   needed (`!hasAMR(sess.AMR, "otp")`):
   - `prompt=none` returns `interaction_required`.
   - User has MFA: `state.SaveChallenge` then redirect to `/login/mfa?c=<id>` (step-up of the
     existing session, `Challenge.SessionID` is set).
   - User has no MFA yet but must have it: redirect to `/account/mfa?return_to=...` (enrollment).
5. **Issue the code.** `password.Random(32)`, `state.SaveCode` with client, redirect URI, user,
   scope, nonce, PKCE challenge, auth time, `amr`, `acr` and session id. Redirect with
   `code`, `state` and `iss` (RFC 9207).

### 4.2 Login — `loginForm`, `loginSubmit` (`authorize.go`)

`loginSubmit`:

1. `csrfOK` (double submit cookie plus `Origin` check, `server.go`).
2. `account.PasswordLogin` (`internal/account/account.go`):
   - Rate limit with `state.Allow`: 20 per 5 minutes per IP and 5 per 15 minutes per e-mail.
   - Unknown, disabled or password-less user: `password.DummyVerify` so the time is the same as
     for a wrong password. Both return `ErrInvalidCredentials` (the page says "Wrong e-mail or
     password").
   - `password.Verify`, then `state.Reset` of the e-mail counter.
3. The old `sid` session of the browser is ended (`acct.EndSession`): no session fixation.
4. When `user.MustChangePassword` (an admin created by the setup Job, see section 3): no session yet.
   `state.SaveChallenge` with `Purpose = password`, redirect to `/login/password?c=<id>`
   (section 4.4). The steps below run after the new password was set (`continueLogin`).
5. `acct.MFARequirement(user)` decides (`continueLogin`):
   - `Verify`: `state.SaveChallenge` (`amr=[pwd]`, no session yet), redirect to `/login/mfa`.
     The session is created only after both factors.
   - `Enroll`: `startSession` with `amr=[pwd]`, redirect to `/account/mfa?return_to=...`.
   - `NoMFA`: `startSession` with `amr=[pwd]`, redirect to `return_to`.
6. `startSession` creates the Redis session (`state.CreateSession`) and sets the `sid` cookie
   (`HttpOnly`, `SameSite=Lax`, `__Host-` prefix and `Secure` outside local http).

`return_to` is passed through `safeReturn`, which only accepts `/oauth2/authorize?...` and
`/account/mfa`: no open redirect.

Login with password and MFA (user already has MFA):

```mermaid
sequenceDiagram
    participant B as Browser
    participant I as identity
    participant R as Redis
    participant P as Postgres

    B->>I: POST /login (email, password, csrf)
    I->>R: Allow login:ip, login:email
    I->>P: UserByEmail, argon2id verify
    I->>R: SaveChallenge amr=[pwd] (5 min), no session yet
    I-->>B: 303 /login/mfa?c=id
    B->>I: POST /login/mfa (code, csrf)
    I->>R: Attempt(id, 5), Allow mfa:user
    I->>P: open factor, match TOTP, AdvanceMFAStep
    I->>R: DeleteChallenge, CreateSession amr=[pwd, otp]
    I-->>B: 303 return_to + Set-Cookie sid
```

### 4.3 Second factor at login — `mfaForm`, `mfaSubmit`

1. `state.PeekChallenge` to show the form (no attempt counted).
2. `mfaSubmit`: `csrfOK`, then `state.Attempt(id, 5)`: counts atomically, and after 5 tries
   deletes the challenge (the user must enter the password again).
3. A second limit of 15 attempts per 10 minutes per user (`state.Allow` `mfa:user:<id>`).
4. `account.VerifySecondFactor` (see section 8.3).
5. Success: `state.DeleteChallenge`. If `Challenge.SessionID == ""` it was a login: `startSession`
   with `amr=[pwd, otp]`. Otherwise it was a step-up: `upgradeSession` adds `otp` to the
   existing session (`state.UpdateSession`, TTL kept). Then redirect to `safeReturn(ReturnTo)`.

### 4.4 Forced password change — `passwordChangeForm`, `passwordChangeSubmit` (`pages.go`)

For a user with `must_change_password` (the admin made by the setup Job). The password the user typed is
temporary: somebody else knows it, so no session, MFA step or authorization code exists until it is replaced.

1. `passwordChangeForm`: `state.PeekChallenge` must exist and have `Purpose == password` (a second factor
   challenge is not accepted here, and a password challenge is refused by `/login/mfa`).
2. `passwordChangeSubmit`: `csrfOK`, then `state.Attempt(id, 10)`. The user must still exist, be enabled and have
   the flag. The two fields must be equal.
3. `account.SetPassword(user, new, check=true)`: `password.Check` (policy, not the e-mail, not the same as the
   old one), `store.SetUserPassword` (which also clears `must_change_password`), `RevokeUserAccess`, mail
   "password changed".
4. `state.DeleteChallenge`, reload the user, then `continueLogin` (the MFA requirement, the session, the redirect to
   `return_to`). `authorize` also forces a login for a session whose user still has the flag.

```mermaid
sequenceDiagram
    participant B as Browser
    participant I as identity
    participant R as Redis
    participant P as Postgres

    B->>I: POST /login (email, temporary password)
    I->>P: UserByEmail, argon2id verify
    I->>R: SaveChallenge purpose=password (5 min), no session
    I-->>B: 303 /login/password?c=id
    B->>I: POST /login/password (new password twice, csrf)
    I->>R: Attempt(id, 10)
    I->>P: SetUserPassword (clears must_change_password)
    I->>R: DeleteChallenge, then MFA step or CreateSession
    I-->>B: 303 return_to + Set-Cookie sid
```

## 5. Token endpoint — `POST /oauth2/token`

`Server.tokenEndpoint` (`internal/oauth/tokens.go`):

1. `authenticateClient`: `client_secret_basic`, `client_secret_post`, or `client_id` alone for a
   public client. The secret is compared in constant time against `Client.SecretHash`. An
   unknown client costs the same work as a real one.
2. The grant must be in `client.AllowedGrants`.
3. Dispatch on `grant_type`:

| `grant_type` | Function | Who uses it |
| --- | --- | --- |
| `authorization_code` | `grantCode` | Browser apps after login |
| `refresh_token` | `grantRefresh` | Browser apps |
| `client_credentials` | `grantClientCredentials` | Services calling services |
| `urn:ietf:params:oauth:grant-type:token-exchange` | `grantExchange` | The gatekeeper |

Errors are `*token.Error` and rendered by `tokenFail` (OAuth JSON). Anything else is logged and
returns `server_error` without details.

```mermaid
flowchart TD
    T[POST /oauth2/token] --> AC{client authenticated?}
    AC -- no --> F1[401 invalid_client]
    AC -- yes --> G{grant allowed for client?}
    G -- no --> F2[400 unauthorized_client]
    G -- yes --> S{grant_type}
    S -- authorization_code --> C1[grantCode]
    S -- refresh_token --> C2[grantRefresh]
    S -- client_credentials --> C3[grantClientCredentials]
    S -- token-exchange --> C4[grantExchange]
    C1 --> UT[userTokens: access, id, refresh]
    C2 --> UT
    C3 --> SV[access token of the service]
    C4 --> EX[short access token with act]
```

### 5.1 `authorization_code` — `grantCode`

```mermaid
sequenceDiagram
    participant A as Application
    participant I as identity
    participant R as Redis
    participant P as Postgres

    A->>I: POST /oauth2/token grant=authorization_code, code, code_verifier, redirect_uri
    I->>P: ClientByID, compare secret hash
    I->>R: TakeCode (GETDEL)
    I->>I: client, redirect_uri and PKCE must match
    I->>P: UserByID, UserPermissions, UserRoles
    I->>P: InsertRefreshToken (if offline_access)
    I->>R: AddSessionClient
    I-->>A: access_token, id_token, refresh_token
```

1. `state.TakeCode`: reads and deletes in one step, so a code works once.
2. The code must belong to this client, the same `redirect_uri`, and `pkceOK(code_verifier,
   challenge)` (S256, constant time).
3. The user must still exist and be enabled.
4. `userTokens` (below), then `state.AddSessionClient` so logout knows which clients to notify.

### 5.2 `userTokens` — what is issued

- `store.UserPermissions` and `store.UserRoles` are read from the database now.
- Access token: `token.Service.Access`. Audience is `client.Resource`. Lifetime is the client
  `AccessTokenTTL`, else `IDENTITY_ACCESS_TOKEN_TTL` (10 min). Claims include `sub`, `roles`,
  `perms`, `scope`, `amr`, `acr`, `sid`, `auth_time`.
- ID token (only with scope `openid`): `token.Service.ID`. `name` with scope `profile`, `email`
  with scope `email`, `nonce`, `at_hash`.
- Refresh token (only with `offline_access` and grant `refresh_token`): random 48 bytes,
  stored by digest with `store.InsertRefreshToken` (family, session, scope, `amr`, expiry).

### 5.3 `refresh_token` — `grantRefresh`

1. `store.ConsumeRefreshToken(digest, client)` marks the token used and returns it.
   - A token already used: the whole family is revoked (theft detection) and `ErrRefreshReused`.
   - Unknown, revoked, expired or another client's: `ErrRefreshInvalid`.
   Both are `invalid_grant` to the caller (the reuse is logged as a warning).
2. The user must be active.
3. The scope can only narrow. `acr=mfa` when the original login had `otp`.
4. `userTokens` with the same `familyID`: a new refresh token in the same family. Permissions
   are read again, so a role change applies at the next refresh.

```mermaid
sequenceDiagram
    participant A as Application
    participant I as identity
    participant P as Postgres

    A->>I: POST /oauth2/token grant=refresh_token, refresh_token
    I->>P: ConsumeRefreshToken (mark used)
    alt token already used
        I->>P: revoke the whole family
        I-->>A: 400 invalid_grant
    else valid
        I->>P: UserByID, permissions, roles (read again)
        I->>P: InsertRefreshToken (same family)
        I-->>A: new access_token, id_token, refresh_token
    end
```

### 5.4 `client_credentials` — `grantClientCredentials`

```mermaid
sequenceDiagram
    participant S as Service (confidential client)
    participant I as identity
    participant P as Postgres

    S->>I: POST /oauth2/token grant=client_credentials, audience, scope
    I->>P: ExchangePolicyFor(client, audience)
    I->>P: ClientPermissions (roles of the client)
    I->>I: NarrowScope, FilterPerms(audience)
    I-->>S: access_token (sub = client id)
```

For service to service calls. Confidential clients only.

1. `audience` is required.
2. `store.ExchangePolicyFor(client, audience)` must exist (`access_denied` otherwise).
3. Scope: `token.NarrowScope(requested, client scopes, policy.MaxScope)`.
4. Permissions of the client: `store.ClientPermissions` (from the roles given with
   the admin app or `AssignRole`, or `roles` in the setup config), cut to the audience by `token.FilterPerms`.
5. `token.Service.Access` with `Subject = ClientID`.

### 5.5 Token exchange — `grantExchange` and `token.Service.Exchange`

Used by the gatekeeper to turn the user token (audience = gatekeeper resource) into a short token for one
upstream service (RFC 8693). `Exchange` in `internal/token/token.go`:

```mermaid
sequenceDiagram
    participant G as gatekeeper
    participant I as identity
    participant R as Redis
    participant P as Postgres
    participant S as upstream service

    G->>I: POST /oauth2/token grant=token-exchange, subject_token, audience
    I->>I: verify signature, expiry, aud = gatekeeper resource
    I->>R: Denied(jti), Cutoff(user)
    I->>P: ExchangePolicyFor(gatekeeper, audience)
    I->>P: user (active?), permissions, roles
    I->>I: NarrowScope, FilterPerms(audience), TTL 2 min, act = gatekeeper
    I-->>G: access_token for the audience
    G->>S: gRPC call with that token
    S->>S: verify with JWKS, check perms
```

1. Input checks: `subject_token` present, token types are access tokens, exactly one `audience`.
2. `VerifyAccess(subject_token, caller.Resource)`: our signature, expiry, audience equals the
   caller's resource, not on the denylist, not before the user's cutoff (`checkLive`).
3. `store.ExchangePolicyFor(caller, audience)` must exist. The delegation depth
   (`Act.Depth()+1`) must not pass `MaxChainDepth`.
4. Subject is a user (user must be active, permissions and roles re-read from the database) or
   a service (a `client_credentials` token forwarded by the gatekeeper: the permissions of its
   roles).
5. Scope narrows with `NarrowScope` (token scope and policy max). Permissions are cut with
   `FilterPerms` so a service never sees the permissions of another one.
6. Lifetime: `IDENTITY_EXCHANGE_TOKEN_TTL` (2 min), never longer than what is left of the
   subject token.
7. New access token with `act = {sub: caller}` (and the previous `act` chain). The log line has
   `sub`, `act`, `audience`, `scope`, `subject_jti`, `jti`.

## 6. Other token endpoints

```mermaid
flowchart LR
    T[token] --> V{verify and check live}
    V -- revoke: JWT --> D[Redis deny jti until exp]
    V -- revoke: opaque --> RR[Postgres revoke refresh token]
    V -- introspect --> J[active true/false + claims]
    V -- userinfo --> U[sub, name, locale, email by scope]
```

### 6.1 `POST /oauth2/revoke` — `revoke` (RFC 7009)

Client authenticated. Always answers 200 (no oracle on the token).
- JWT (two dots): `tokens.VerifyAny`, and if it belongs to the client, `state.Deny(jti, remaining life)`.
- Anything else is a refresh token: `store.RevokeRefreshByHash`.

### 6.2 `POST /oauth2/introspect` — `introspect` (RFC 7662)

Confidential clients only. `VerifyAny`, type must be `access`, then `tokens.IsLive`
(denylist and cutoff). Returns `active`, `sub`, `client_id`, `scope`, `aud`, `jti`, `exp`, `iat`,
`iss` and the `act` chain. The gRPC `Introspect` (section 9) does the same.

### 6.3 `GET/POST /userinfo` — `userinfo`

Bearer access token with scope `openid`, live, and for a user (not a service). Returns `sub`,
plus `name`, `locale` (scope `profile`) and `email` (scope `email`).

### 6.4 Discovery and keys — `discovery`, `jwks`

Static documents cached 5 minutes. `jwks` serves `keys.Set.JWKS` (current plus retired keys).
Services verify tokens locally with these keys (`gocommon/jwtx`).

## 7. Logout

```mermaid
sequenceDiagram
    participant B as Browser
    participant I as identity
    participant R as Redis
    participant P as Postgres
    participant A as Client back-channel endpoint

    B->>I: GET /oauth2/logout?id_token_hint&post_logout_redirect_uri&state
    alt hint valid
        I->>I: trusted, no confirmation
    else no hint
        I-->>B: confirmation page
        B->>I: POST /oauth2/logout (csrf)
    end
    I->>R: DeleteSession
    I->>P: RevokeRefreshBySession
    I-->>B: clear sid cookie, 302 registered post_logout_redirect_uri
    I-)A: POST logout_token (background, 3 tries)
```

### 7.1 RP initiated logout — `endSession` (`pages.go`)

`GET` or `POST /oauth2/logout`.

1. With `id_token_hint`: `tokens.VerifyIDHint` (an expired one is fine up to the refresh
   token lifetime, a forged one is not). The client is the `aud`. This is trusted: logout
   happens at once.
2. Without a hint: a confirmation page with a POST form (`confirm-logout`), and the POST needs
   `csrfOK`. This stops another site from signing people out with an image tag.
3. `post_logout_redirect_uri` is used only if it is registered for the client.
4. `account.EndSession(publicID)`, the `sid` cookie is cleared.

### 7.2 `account.EndSession` and back-channel logout

`internal/account/account.go`:

1. `state.DeleteSession` (removes the session and returns it).
2. `store.RevokeRefreshBySession` revokes the refresh tokens of that session.
3. `backchannel(session)`: for each client in `Session.Clients` that has a
   `BackchannelLogoutURI`, a background task signs a logout token (`token.Service.Logout`, 2 min,
   event `backchannel-logout`) and POSTs it (`postLogout`), 3 attempts with growing delay.
   Failures are logged, never fatal.

### 7.3 `account.RevokeUserAccess` — end everything for a user

```mermaid
flowchart TD
    E[password change or reset / user disabled / MFA reset] --> RU[RevokeUserAccess]
    RU --> S1[Redis: delete all sessions of the user]
    RU --> S2[Postgres: revoke all refresh tokens]
    RU --> S3[Redis: cutoff = now, kept AccessTTL + 1 min]
    S1 --> BC[back-channel logout to each client]
    S3 --> N[introspection and exchange refuse older tokens]
```

Used by password change, reset, disabling a user and MFA reset.
1. `state.DeleteUserSessions` (and back-channel logout for each).
2. `store.RevokeRefreshByUser`.
3. `state.SetCutoff(user, now, AccessTTL + 1 min)`: access tokens issued before this moment are
   refused by introspection and token exchange. Services that verify locally stop accepting
   them when the token expires (at most the access token lifetime).

## 8. Account flows (HTML pages)

### 8.1 Password reset

```mermaid
sequenceDiagram
    participant U as User
    participant I as identity
    participant P as Postgres
    participant C as courier

    U->>I: POST /password/forgot (email)
    I->>I: rate limit (IP 10/h, e-mail 3/h)
    I->>P: UserByEmail
    I->>P: CreatePasswordReset(digest(token), 30 min)
    I-->>U: same answer whether the e-mail exists or not
    I-)C: SendNotification (background)
    U->>I: GET /password/reset?token
    I->>P: PeekPasswordReset
    U->>I: POST /password/reset (token, new password)
    I->>P: ConsumePasswordReset (atomic)
    I->>P: SetUserPassword
    I->>I: RevokeUserAccess
```

- `forgotSubmit` calls `account.RequestReset`: rate limits per IP and per e-mail (over the limit
  it still answers the same), unknown or disabled users return `nil`, so the answer never
  reveals whether the address exists. The mail is sent in the background (`Service.background`) so the
  response time does not depend on the outcome.
- `resetForm` calls `account.ResetTokenUser` (peek only).
- `resetSubmit` calls `account.CompleteReset`: the password policy (`password.Check`: length,
  common passwords, not the e-mail, not the same) runs before the token is consumed;
  `store.ConsumePasswordReset` is atomic, so two requests with one token cannot both win; then
  `SetPassword` stores the hash, calls `RevokeUserAccess` and mails "password changed".

### 8.2 MFA enrollment and management (`/account/mfa`)

All handlers return 404 when `IDENTITY_MFA_MODE=off` and need a session (`requireSession`, which
sends the browser to `/login`).

| Step | Handler | Account method |
| --- | --- | --- |
| Show QR code or status | `accountMFA` → `mfaPage` | `BeginEnrollment` (reuses a pending secret, so a reload keeps the QR code) |
| Confirm the first code | `accountMFAConfirm` | `ConfirmEnrollment` |
| Turn off | `accountMFADisable` | `DisableMFA` |

- `BeginEnrollment`: new TOTP secret (`mfa.NewSecret`), sealed with `Sealer.Seal(secret, userID)`,
  stored with `store.ReplaceMFAFactor` (unconfirmed). Returns the base32 secret, the
  `otpauth://` URI and a PNG QR as a data URI.
- `ConfirmEnrollment`: limit 10 per 10 minutes, `mfa.Match` on the first code, then 10 recovery
  codes (`mfa.RecoveryCodes`, stored as digests) and `store.ConfirmMFAFactor`. The page
  shows the codes once and `upgradeSession` marks the session as multi-factor. A mail tells the user.
- `DisableMFA`: refused when MFA is required (`MFAForced`: mode `required` or the user is
  enforced). Otherwise it needs the password and a code, then `AdminDisableMFA` (`store.ResetMFA`).

MFA enrollment:

```mermaid
sequenceDiagram
    participant B as Browser
    participant I as identity
    participant P as Postgres
    participant C as courier

    B->>I: GET /account/mfa (session)
    I->>P: ReplaceMFAFactor (sealed secret, unconfirmed)
    I-->>B: QR code and key
    B->>I: POST /account/mfa (code)
    I->>P: match TOTP, ConfirmMFAFactor, 10 recovery code digests
    I->>I: upgradeSession (add otp)
    I-->>B: recovery codes (shown once)
    I-)C: mail "MFA enabled"
```

### 8.3 Checking a second factor — `account.VerifySecondFactor`

```mermaid
flowchart TD
    V[code from user] --> L{12 characters?}
    L -- yes --> RC[UseRecoveryCode, works once]
    L -- no --> O[openFactor: unseal secret]
    O --> M{Match step -1, 0, +1?}
    M -- no --> X[ErrInvalidCode]
    M -- yes --> AD{AdvanceMFAStep: step is new?}
    AD -- no --> X
    AD -- yes --> OK[accepted]
    RC -- ok --> OK
    RC -- not found --> X
```

- A 12 character input is treated as a recovery code (`mfa.NormalizeRecoveryCode`) and consumed
  with `store.UseRecoveryCode` (works once).
- Otherwise: `openFactor` (unseals the secret; `Sealer.NeedsReseal` re-encrypts with the newest
  key), `mfa.Match` accepts the previous, current and next 30 second step (clock drift), and
  `store.AdvanceMFAStep` accepts a step only once (a code cannot be replayed).

### 8.4 MFA mode matrix — `account.MFARequirement`

| `IDENTITY_MFA_MODE` | User has MFA | User is enforced | Result at login |
| --- | --- | --- | --- |
| `off` | any | any | `NoMFA` |
| any other | yes | any | `Verify` |
| `required` | no | any | `Enroll` |
| `optional` | no | yes | `Enroll` |
| `optional` | no | no | `NoMFA` |

A client can also ask for MFA with `acr_values=mfa`; `authorize` then asks for the code if the
session has no `otp` in its `amr`.

## 9. gRPC administration API — `internal/service/service.go`

Auth: `grpcserver.JWTAuth` (our own JWT with audience `identity`). Authorization:
`grpcserver.WithMethodPermissions(service.Permissions)`: every RPC needs the permission listed in the
`Permissions` map, and an RPC without an entry is denied. Domain errors are mapped by `toErr`
(`store.ErrNotFound` → NotFound, `ErrConflict` → AlreadyExists, password policy → InvalidArgument,
anything else → Internal without details).

| RPC | Permission | Handler logic |
| --- | --- | --- |
| `Introspect` | `identity:token:read` | `VerifyAny` + `IsLive` |
| `CheckPermission` | `identity:permission:read` | `store.UserPermissions` + `authz.Allowed` (disabled user: not allowed) |
| `RevokeToken` | `identity:token:write` | `state.Deny(jti, ttl)` |
| `GetUser`, `ListUsers` | `identity:user:read` | `ListUsers` pages by e-mail (page token = base64 of last e-mail, size 50, max 200) |
| `CreateUser` | `identity:user:write` | e-mail checks, `password.Check` and `Hash`, `store.CreateUser` |
| `SetUserDisabled` | `identity:user:write` | disabling also calls `RevokeUserAccess` |
| `SetUserPassword` | `identity:user:write` | `account.SetPassword(check=true)` |
| `SendPasswordReset` | `identity:user:write` | `account.SendReset` |
| `CreateRole`, `SetRolePermissions`, `AssignRole`, `RevokeRole` | `identity:role:write` | `authz.Valid` on each permission; roles go to a user **or** a client |
| `ListRoles` | `identity:role:read` | |
| `CreateClient`, `RotateClientSecret` | `identity:client:write` | validates grants and URIs; a public client cannot use `client_credentials` or exchange; the secret is returned once |
| `ListClients` | `identity:client:read` | |
| `SetExchangePolicy` | `identity:exchange:write` | `max_chain_depth` 1 to 5; `delete` removes the policy |
| `ListExchangePolicies` | `identity:exchange:read` | |
| `GetUserMFA` | `identity:mfa:read` | |
| `SetUserMFA`, `EnforceUserMFA`, `ResetUserMFA` | `identity:mfa:write` | Admin methods of `account` (turn off, enforce, reset and end sessions) |

Note: there is no RPC to add a redirect URI to a client. That is only the setup Job (`redirect_uris` and `post_logout_uris` in `SETUP_CONFIG`, merged into the stored lists).

## 10. The gatekeeper (BFF) end to end

The gatekeeper is the only public entry point of the platform for browsers, mobile apps and
services. It is a pure JSON to gRPC mapper plus the OIDC login. The browser never sees a token:
it only holds an opaque `HttpOnly` session cookie. Code is in `../gatekeeper` (module
`github.com/huponx/gatekeeper`).

### 10.1 Map of the gatekeeper code

| File | Role |
| --- | --- |
| `cmd/gatekeeper/main.go` | Wiring: routes, Redis, session store, OIDC discovery, JWKS verifier, token exchange client, gRPC proxy, HTTP server. |
| `internal/routes/routes.go` | Loads and validates `routes.yaml` (`routes.Parse`). |
| `internal/bff/bff.go` | HTTP handlers: `/auth/*` and every configured route (`Server.route`). |
| `internal/session/session.go` | Sessions in Redis, tokens sealed with AES-GCM, login state, refresh lock, back-channel indexes. |
| `internal/proxy/proxy.go` | JSON to gRPC call without generated stubs (descriptor set or reflection). |
| `internal/appconfig/appconfig.go` | `GATEKEEPER_*` environment variables. |
| `gocommon/oidcclient` | Relying party: `AuthURL` (PKCE), `Exchange`, `Refresh`, `Revoke`, `EndSessionURL`, `VerifyLogoutToken`. |
| `gocommon/tokenexchange` | `ExchangeToken` (RFC 8693) and `ServiceToken` (client credentials), both cached. |
| `gocommon/authn` | `Verify` (access token to `Principal`), `Principal.Can(permission)`. |

Fixed endpoints, registered in `bff.Server.Routes`:

| Endpoint | Handler | Purpose |
| --- | --- | --- |
| `GET /auth/login` | `login` | Start the OIDC code flow |
| `GET /auth/callback` | `callback` | Finish it and create the session |
| `GET /auth/me` | `me` | Who am I (sub, roles, scopes, perms, amr, `csrf_token`, expiry) |
| `POST /auth/logout` | `logout` | End session, revoke refresh token, return the identity logout URL |
| `POST /auth/backchannel-logout` | `backchannelLogout` | Receives the logout token from identity |
| `GET /healthz`, `/readyz` | `healthz` | Liveness, readiness (Redis) |
| any route of `routes.yaml` | `route` | JSON to gRPC |

`/auth/*`, `/healthz` and `/readyz` are reserved: a route in `routes.yaml` cannot use them.

### 10.2 Startup — `cmd/gatekeeper/main.go`

1. `routes.Load(GATEKEEPER_ROUTES_FILE)`: rejects unknown fields, unknown upstreams, duplicate
   routes, bad methods, reserved paths. A route needs `permission` or `public: true`, never both
   (deny by default).
2. Redis and `session.New` with `GATEKEEPER_SESSION_KEY` (first key seals, the others only open).
3. `oidcclient.Discover(GATEKEEPER_IDENTITY_ISSUER)` with `GATEKEEPER_CLIENT_ID` and
   `GATEKEEPER_CLIENT_SECRET`. The redirect URL is `GATEKEEPER_PUBLIC_URL/auth/callback` and must be
   registered on the identity client (`redirect_uris` in the setup config).
4. `jwtx.NewRemoteKeySet` on the identity `jwks_uri` and a `Verifier` for issuer and
   `GATEKEEPER_AUDIENCE` (this must equal the `resource` of the gatekeeper client in identity).
5. `tokenexchange.New` on the identity `token_endpoint`.
6. `proxy.New` and `proxy.Check`: with a descriptor set a typo is a start-up error, with reflection it
   only warns (the upstream may not be up yet).
7. HTTP server: `bff.Server.Routes`.

### 10.3 Login — `login` and `callback`

```mermaid
sequenceDiagram
    participant B as Browser
    participant G as gatekeeper
    participant R as Redis
    participant I as identity

    B->>G: GET /auth/login?return_to=...
    G->>G: oidc.AuthURL (state, nonce, PKCE verifier, acr_values)
    G->>R: PutLogin(state) sealed, 10 min
    G-->>B: Set-Cookie login-state-xxxx, 302 identity /oauth2/authorize
    B->>I: authorize and login (section 4)
    I-->>B: 302 GATEKEEPER_PUBLIC_URL/auth/callback?code&state
    B->>G: GET /auth/callback?code&state (login-state cookie)
    G->>G: state must equal the cookie of this browser
    G->>R: TakeLogin(state) (GETDEL, single use)
    G->>I: POST /oauth2/token (code, code_verifier, client secret)
    I-->>G: access, id and refresh token
    G->>R: Create session (tokens sealed, CSRF token, indexes by sub and sid)
    G-->>B: Set-Cookie session (new id), 302 return_to
```

- `login`: `return_to` goes through `safeReturn` (a path of this site, or an absolute URL on one
  of `GATEKEEPER_UI_ORIGINS`), otherwise `GATEKEEPER_POST_LOGIN_URL`. Every attempt has its own
  cookie `login-state-<hash>` (several tabs do not overwrite each other). `GATEKEEPER_ACR_VALUES=mfa`
  asks identity for a second factor on every login.
- `callback`: an `error` from identity gives 401 `login_failed`. The ID token is verified by
  `oidcclient.Exchange` (nonce included). A token without `sub` is refused.
- The session is created by `session.Store.Create`: new random id at every login (no session
  fixation), CSRF token of 24 random bytes, sets `gk:sid:<identity sid>` and `gk:sub:<sub>`
  for back-channel logout.
- Cookie name is `__Host-session` outside local http (`Secure`, `HttpOnly`, `SameSite=Lax`).

### 10.4 Authenticating a request — `authenticate`

Two modes, chosen by the request:

| Mode | When | What happens |
| --- | --- | --- |
| Session cookie | no `Authorization` header (browser) | Loads the session, refreshes the tokens if they expire in less than 30 s, verifies the access token. |
| Bearer | any `Authorization` header (mobile app, service) | `authenticateBearer` verifies the token locally. No session is stored. A malformed header is 401, never a fallback to the cookie. |

Cookie mode, in order:

1. No cookie or session not found: 401 `unauthenticated` (cookie cleared).
2. `session.Store.Get` slides the idle timeout, never beyond the absolute lifetime (`GATEKEEPER_SESSION_IDLE_TTL` 8 h, `GATEKEEPER_SESSION_ABSOLUTE_TTL` 168 h).
3. Token near expiry: `refresh` (below).
4. `authn.Verify(access token)`: signature (JWKS), issuer, audience, expiry and type. An invalid token
   deletes the session (key rotated away, user revoked). If the JWKS cannot be loaded it is 503, not a logout.
5. The `Principal` (sub, roles, scopes, perms, amr) is put on the request context.

A revoked token still verifies locally until it expires, so keep the access token lifetime short
(`IDENTITY_ACCESS_TOKEN_TTL`, 10 min). Disabling a user ends the identity session and refresh
tokens at once, and the gatekeeper session ends at the next refresh or through back-channel logout.

### 10.5 Refresh — `refresh`

```mermaid
sequenceDiagram
    participant G1 as gatekeeper replica 1
    participant G2 as gatekeeper replica 2
    participant R as Redis
    participant I as identity

    G1->>R: Lock gk:lock (10 s)
    G2->>R: Lock fails, wait up to 3 s polling the session
    G1->>R: read session again (maybe already fresh)
    G1->>I: POST /oauth2/token grant=refresh_token
    alt invalid_grant (revoked, expired or reused)
        G1->>R: delete session
        G1-->>G1: 401 sign in again
    else ok
        I-->>G1: new access and refresh token (rotation)
        G1->>R: Update session (same lifetime)
        G2->>R: sees fresh tokens, continues
    end
```

Only one replica refreshes, because two replicas using the same refresh token would trigger the
reuse detection of identity (`store.ConsumeRefreshToken`) and revoke the whole family.

### 10.6 A routed call — `Server.route`

For each entry of `routes.yaml`, in this order:

```mermaid
flowchart TD
    A[HTTP request on a route] --> B[authenticate: cookie or Bearer]
    B -- fail --> X1[401 / 503]
    B --> C{not GET and cookie mode?}
    C -- yes --> D{checkWrite: Origin in UI origins and Csrf-Token equals session CSRF?}
    D -- no --> X2[403 bad_origin / bad_csrf]
    D -- yes --> E
    C -- no --> E{route public or Principal.Can permission?}
    E -- no --> X3[403 forbidden, early]
    E -- yes --> F[requestJSON: body + query + path params]
    F -- bad JSON or Content-Type --> X4[400 invalid_request]
    F --> G[ExchangeToken: aud of the route, 2 min token]
    G -- ErrDenied --> X5[403 forbidden]
    G -- other --> X6[502 unavailable]
    G --> H[proxy.Call: protojson to dynamic message, gRPC invoke with Bearer]
    H -- error --> I[writeError: gRPC code to HTTP]
    H --> J[200 JSON, unpopulated fields included]
```

- `requestJSON`: the JSON object body (only for non-GET, `Content-Type: application/json`, max 1 MiB),
  then the query string (a repeated key becomes an array), then the path parameters. Path parameters
  win, so `{user_id}` always fills `user_id`. The result is unmarshalled by `protojson` into the
  request message of the method, so an unknown field is a 400.
- `ExchangeToken(session access token, route audience)`: the audience defaults to the upstream name. The
  result is cached by `tokenexchange` per (subject token, audience, scope) until shortly before it expires.
  Identity enforces the policy (section 5.5).
- `proxy.Call`: `resolve` finds the method (descriptor set, or gRPC reflection with a service token
  `exch.ServiceToken(audience)`, cached 10 minutes), `dynamicpb` builds the messages, the call carries
  `authorization: Bearer <exchanged token>`. Streaming methods are refused.
- The upstream checks the token again. For identity that is `grpcserver.JWTAuth` and then the
  permission of the method in `service.Permissions` (section 9). The permission in `routes.yaml`
  must be the same one, so the early 403 never disagrees with the upstream.

Error mapping — `writeError` and `mapCode`:

| gRPC code | HTTP | `error.code` |
| --- | --- | --- |
| InvalidArgument, OutOfRange | 400 | `invalid_argument` |
| NotFound | 404 | `not_found` |
| AlreadyExists, Aborted | 409 | `conflict` |
| FailedPrecondition | 412 | `failed_precondition` |
| PermissionDenied | 403 | `forbidden` |
| Unauthenticated | 502 | `upstream_auth` (the gatekeeper's own token was refused, not the user's fault) |
| ResourceExhausted | 429 | `rate_limited` |
| Unavailable | 503 | `unavailable` |
| DeadlineExceeded | 504 | `timeout` |
| Unimplemented | 501 | `unimplemented` |
| other | 500 | `internal` |

For 5xx the message is replaced by "the service failed to process the request" (details only in the log).
All errors have the form `{"error": {"code": "...", "message": "..."}}`.

### 10.7 Logout

```mermaid
sequenceDiagram
    participant B as Browser
    participant G as gatekeeper
    participant R as Redis
    participant I as identity

    B->>G: POST /auth/logout?return_to=https://app/ (Origin, Csrf-Token)
    G->>G: checkWrite
    G->>R: delete session
    G->>I: POST /oauth2/revoke (refresh token)
    G-->>B: {"logout_url": identity /oauth2/logout?id_token_hint&post_logout_redirect_uri}
    B->>I: GET logout_url
    I->>I: EndSession (section 7)
    I-)G: POST /auth/backchannel-logout (logout_token)
    G->>G: VerifyLogoutToken
    G->>R: delete sessions of that sid (or of the sub)
    I-->>B: 302 registered post_logout_redirect_uri
```

- `logout` without a valid session still returns 200 with the logout URL (idempotent).
- `return_to` must be a UI origin and also registered as a post-logout URI of the client in identity.
- `backchannelLogout` is called by identity (`account.backchannel`): `DeleteByIDPSession(sid)` when the
  token has `sid`, otherwise `DeleteBySubject(sub)`. The client in identity needs
  `backchannel_logout_uri = <public url>/auth/backchannel-logout`. This is how a logout in
  one application, a password reset or a disabled user ends the gatekeeper sessions right away.

### 10.8 CORS and origins

`bff.Server.cors` answers only the browsers of `GATEKEEPER_UI_ORIGINS` (credentials allowed, never
`*`), and answers preflights before authentication. With no UI origins configured only the gateway
origin itself is accepted. The same list is used for `checkWrite` and `safeReturn`.

### 10.9 Whole picture

```mermaid
sequenceDiagram
    participant B as Browser (admin app)
    participant G as gatekeeper
    participant R as Redis (gatekeeper)
    participant I as identity
    participant S as upstream service (gRPC)

    B->>G: GET /api/users (cookie)
    G->>R: load session, refresh if needed
    G->>G: verify access token with JWKS, Principal.Can("identity:user:read")
    G->>I: token exchange (aud identity), cached
    I-->>G: 2 minute token with act = gatekeeper
    G->>S: ListUsers(JSON turned into protobuf) + Bearer
    S->>S: verify JWT, service.Permissions check, handler
    S-->>G: protobuf reply
    G-->>B: 200 JSON
```

When the upstream is another service than identity (for example courier), the same steps apply:
add an upstream, routes and an exchange policy (an exchange policy `gatekeeper -> <aud>`, in the admin app or `exchange_policies` of the setup config). A call that needs several gRPC methods belongs in one method of a service, not in the gatekeeper.

## 11. Security properties and where they are enforced

| Property | Where |
| --- | --- |
| No open redirect | `authorize` (redirect URI must be registered), `safeReturn`, `endSession` (registered logout URIs) |
| PKCE S256 required | `authorize`, `pkceOK` |
| Code works once, 60 s | `state.TakeCode` (GETDEL), `codeTTL` |
| CSRF on forms | `csrfOK`: double submit cookie + `Origin` |
| No session fixation | `loginSubmit` ends the old session |
| No user enumeration | `DummyVerify`, same message, `RequestReset` answers the same |
| Brute force limits | `state.Allow` (login, reset, MFA confirm, MFA disable, MFA user), `state.Attempt` (5 per challenge) |
| TOTP replay | `store.AdvanceMFAStep` |
| Refresh token theft | `store.ConsumeRefreshToken` revokes the family on reuse |
| Immediate revocation | denylist (`state.Deny`) and cutoff (`state.SetCutoff`), checked by `checkLive` |
| Least privilege on exchange | `ExchangePolicyFor`, `NarrowScope`, `FilterPerms`, 2 minute TTL, `act` claim |
| Secrets at rest | hashes for passwords, secrets, tokens; AES-GCM for TOTP |
| Key rotation | `keys.Load` keeps retired keys in the JWKS; `Sealer` re-seals on read |
| Browser never holds a token | gatekeeper `session.Store`: opaque cookie, tokens sealed with AES-GCM in Redis |
| CSRF on JSON calls | gatekeeper `checkWrite`: `Origin` in UI origins and `Csrf-Token` equals the session token (cookie mode only) |
| Early deny | gatekeeper `Principal.Can(route.Permission)`; identity checks again with `service.Permissions` |
| One refresh at a time | gatekeeper `session.Store.Lock`, so refresh token reuse detection is not triggered |
| Sessions end on logout events | gatekeeper `backchannelLogout` with the indexes `gk:sid:` and `gk:sub:` |
