# New Realm Checklist

Steps to provision a new Keycloak realm for an Equabli environment/tenant. Do these in order —
the auth flow step depends on this SPI's jar already being deployed to the Keycloak server (see
[README.md](README.md#deploy)).

> Items marked **⚠️ undocumented** aren't backed by any config found in the workspace at the time
> of writing — confirm exact values with whoever owns that system before relying on them.

## 1. Cloudflare Access OIDC client

Cloudflare Access is the identity provider gate in front of the realm's apps; this client lets
Cloudflare Access authenticate against Keycloak via OIDC. ⚠️ **Undocumented** — no Cloudflare-side
Keycloak client config exists anywhere in this workspace (checked for realm exports, Terraform,
and app config; only the *reverse* integration is documented — identity-service validating the
`Cf-Access-Jwt-Assertion` header Cloudflare issues, in `eq-identity-service`'s
`CloudflareAccessProperties`/`SecurityConfig`). The steps below are the standard Cloudflare
Access + generic-OIDC requirements — verify against the live Cloudflare Zero Trust dashboard.

In Keycloak (**Clients → Create client**):

- **Client ID**: `cloudflare-oidc-<env>` (e.g. `cloudflare-oidc-dev`)
- **Client type**: OpenID Connect
- **Client authentication**: On (confidential — Cloudflare Access needs a client secret)
- **Standard flow** (Authorization Code): On
- **Direct access grants**: Off
- **Valid redirect URIs**: `https://<your-team-name>.cloudflareaccess.com/cdn-cgi/access/callback`
- **Assigned scopes**: default (`openid`, `email`, `profile`) — Cloudflare Access needs an `email`
  claim in the ID token

After saving, go to the **Credentials** tab and copy the client secret. In the Cloudflare Zero
Trust dashboard (**Settings → Authentication → Add new → OIDC**):

| Cloudflare field | Value |
|---|---|
| App ID | the Keycloak client ID above |
| Client secret | from Keycloak's Credentials tab |
| Auth URL | `https://<keycloak-host>/realms/<realm>/protocol/openid-connect/auth` |
| Token URL | `https://<keycloak-host>/realms/<realm>/protocol/openid-connect/token` |
| Certificate URL | `https://<keycloak-host>/realms/<realm>/protocol/openid-connect/certs` |
| Scopes | `openid email profile` |

## 2. `identity-service` client (token validation)

`eq-identity-service` reads this **exact** client ID (`identity-service`) from its
`application.yaml` (`keycloak.client-id`) and uses it for two things — keep both working when you
create it:

- **Admin operations** (`KeycloakConfig` builds a Keycloak admin client via the
  `client_credentials` grant) — for user CRUD during migration/provisioning.
- **Token introspection** (`TokenValidation`, RFC 7662) — validates access tokens issued to other
  clients in the realm.

In Keycloak (**Clients → Create client**):

- **Client ID**: `identity-service` (must match the value identity-service is configured with for
  this realm — see its `application.yaml`)
- **Client type**: OpenID Connect
- **Client authentication**: On (confidential)
- **Service accounts roles**: On (required for the `client_credentials` admin-client usage)
- **Standard flow**: Off (this client never does a browser login)
- **Direct access grants**: Off

After saving, under **Service account roles**, assign the `realm-management` client roles the
admin operations need — at minimum `manage-users`, `view-users`, `query-users`. ⚠️ Cross-check
against `KeycloakConfig`/the admin-client calls in `eq-identity-service` if that service's user
management surface has grown, since the exact role set isn't centralized in one place.

Copy the client secret from the **Credentials** tab and set it in this environment's
`eq-identity-service` config alongside `keycloak.server-url` and `keycloak.realm` for the new
realm.

> **Don't conflate this with `equabli-dev` / `service-client-id`.** identity-service also has a
> separate client (its own ID + secret) used only for internal service-to-service token issuance
> (`VendorTokenService`/`InternalTokenService`). If the new realm/environment needs that too, it's
> a separate client — create and configure it independently.

## 3. Authentication flow (migrated-user setup emails)

Requires this repo's jar already deployed to the target Keycloak server's `providers/` directory
(see [README.md](README.md#deploy)) — the custom authenticator isn't picked up automatically.

1. **Authentication → Flows** → select the realm's default **browser** flow → **Duplicate** (e.g.
   name it `browser - migration setup`).
2. In the duplicated flow's forms subflow, replace the **Username Password Form** execution with
   **Username Password Form (Migration Setup Email)** (same requirement level).
3. **Authentication → Bindings** → set **Browser Flow** to the duplicated flow.
4. For every client whose users go through the migrated-user or forgot-password setup flow,
   register the post-setup redirect forwarder — **with** a trailing `*` — under that client's
   **Valid redirect URIs**:
   `<base-url>/identity-service/api/public/user/post-setup-redirect*`
   where `<base-url>` is whichever base URL this realm actually resolves to (its
   `identityServiceBaseUrl` realm attribute if set, else the server's `IDENTITY_SERVICE_BASE_URL`
   — see step 5 below) (see
   [README.md](README.md#post-setup-redirect-where-the-user-lands-afterwards) for why this has to
   be a stable forwarder rather than the tenant's real URL).
5. Confirm the base URL is resolvable for this realm — either the server-wide
   `IDENTITY_SERVICE_BASE_URL` env var already points at the right identity-service for this realm,
   or (when this realm needs a *different* identity-service than the server default, e.g. a new
   tenant sharing a Keycloak server with other realms) set the realm attribute
   `identityServiceBaseUrl`. There is no admin-console UI for generic realm attributes — use
   `kcadm` or the Admin REST API:
   - **`kcadm`:** `kcadm.sh update realms/<realm> -s 'attributes.identityServiceBaseUrl=https://tenant.equabli.io'`
     (safe — `kcadm update -s` does a read-modify-write, so it won't drop other attributes).
   - **Admin REST API (`PUT /admin/realms/<realm>`):** ⚠️ this endpoint replaces the *entire*
     `attributes` map with whatever you send — any existing key you omit gets deleted. Always
     `GET /admin/realms/<realm>` first, merge `identityServiceBaseUrl` into the returned
     `attributes` object, and `PUT` the full merged map back:
     ```
     curl -s "https://<keycloak-host>/admin/realms/<realm>" -H "Authorization: Bearer $TOKEN" | jq .attributes
     curl -s -X PUT "https://<keycloak-host>/admin/realms/<realm>" \
       -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
       -d '{"attributes": { ...every existing key..., "identityServiceBaseUrl": "https://tenant.equabli.io" }}'
     ```
     Also note: `oauth2DeviceCodeLifespan` / `oauth2DevicePollingInterval` are realm-model fields
     that get silently reset to Keycloak's hardcoded defaults (600s / 5s) on *any* realm PUT that
     omits them at the top level — they are not read from `attributes` despite living there too.
     If this realm has customized either one away from the default, include them as top-level
     fields in the same PUT body (not nested in `attributes`) so they aren't clobbered.
   - **Confirm it took effect:** trigger a forgot-password or migrated-user login attempt on this
     realm and check the Keycloak server log for `Base URL resolved for realm <realm>: <url>
     (source=..., realmAttr=..., env=...)` (logged by
     `IdentityServiceConstants.resolveBaseUrl()`) — `source=realm attribute` confirms the attribute
     won; `source=env var` or `source=default` means it wasn't picked up.

   Also confirm `IDENTITY_SERVICE_RESET_MAIL_SECRET` is set for this environment if not already
   global (see [README.md](README.md#configure-environment-variables-on-the-keycloak-process)).

> **Gotcha:** check the config (gear icon) on the **User session count limiter** execution that
> precedes the password form in the duplicated flow. If it was copied with a stale/leftover
> session-limit config (or one meant for a different realm), it silently rejects every login
> *before* the password form ever renders — a generic `AuthenticationFlowException` in the server
> log with no client-facing error, which looks like a flow-binding or SPI problem but isn't. Leave
> it unconfigured unless this realm actually needs a session cap.

## 4. Password policy

`eq-identity-service` treats Keycloak's realm password policy as the **sole source of truth** for
password validation — it never enforces its own rules, it just relays whatever policy-violation
message Keycloak returns (`KeycloakService#setUserPassword` /
`#setPermanentPasswordClearingActions`, both catch the 400 and surface Keycloak's message). Its
server-generated temporary passwords and the rules shown to users in the temporary-password email
(`PasswordUtils.PASSWORD_POLICY`) **assume**:

- At least 8 characters long
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (`!@#$%^&*`)

In Keycloak (**Realm settings → Authentication → Policies → Password policy** — or **Authentication
→ Password Policy** on older admin consoles), add policy types matching that assumption:

```
length(8) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1)
```

If this realm's policy diverges from that (longer minimum, password history, etc.), the
server-generated temporary passwords can be **rejected by Keycloak on user creation** — the
generator only guarantees an 8-char, no-history-aware password today.

⚠️ **Check before assuming parity is enough**: `eq-sso-service` (the legacy system this SSO
migration replaces) documents a stricter policy in its `messages.properties` — a 14-character
minimum and a block on reusing any of the last 10 passwords
(`password.last.10.match.error`). If this realm needs to match that legacy standard rather than
identity-service's current default, add `length(14)` and `passwordHistory(10)` to the Keycloak
policy — but also bump `PasswordUtils.LENGTH`/`PASSWORD_POLICY` in `eq-identity-service` to match,
since the generator doesn't know about password history and only pads to 14 chars incidentally
(its `LENGTH` constant happens to be 14, but it makes no history guarantee). Confirm with whoever
owns password requirements before picking one over the other.

## 5. Standard token exchange + impersonation permissions (ZTNA clients)

Needed when a client (e.g. `cloudflare-oidc-demo`, for ZTNA) has to obtain a Keycloak token scoped
to another client (e.g. `identity-service`) via RFC 8693 **Standard Token Exchange**. Two different
request shapes hit **two different, unrelated permission checks** — configuring only one leaves the
other failing with a generic error on the login page and a `TOKEN_EXCHANGE_ERROR` event in
**Realm settings → Events**:

| Request shape | Keycloak event `reason` | Permission that governs it |
|---|---|---|
| Exchanging an existing `subject_token` for a different client's audience | `not_allowed` / "client not allowed to exchange" | **Target client**'s `token-exchange` scope (step below) |
| Requesting a token via `requested_subject` (a user ID, no `subject_token`) — i.e. impersonation | "client not allowed to impersonate" | **Users**' `impersonate` scope (step below) — *not* the target client's `token-exchange` scope |

⚠️ The legacy `realm-management` client roles `impersonation` / `manage-users`, assigned to the
requesting client's service account, are **not consulted** by this new fine-grained/Standard Token
Exchange (V2) model — don't rely on them; they only apply to the old admin impersonation REST
endpoint and classic (non-standard) token exchange.

Steps:

1. **Requesting client** (e.g. `cloudflare-oidc-demo`) → **Settings → Capability config**:
   **Client authentication**: On (confidential — it must authenticate itself to call `/token`),
   **Standard Token Exchange**: On, **Service account roles**: On. Save. (Enable this on the
   *requester*, not the target client — enabling it on the target does nothing.)
2. If the flow exchanges an existing `subject_token` for the target client's audience: **target
   client** (e.g. `identity-service`) → **Permissions** → enable → `token-exchange` scope → add a
   policy allowing the requesting client (a `Client` policy naming `cloudflare-oidc-demo` works).
3. If the flow impersonates a user via `requested_subject`: **Users → Permissions** tab (realm-wide,
   not a specific user) → enable → `impersonate` scope → add a policy allowing the requesting
   client (can reuse the same `Client` policy from step 2).
4. ⚠️ If impersonation still fails after step 3, also check the **`user-impersonated`** scope on the
   same **Users → Permissions** page — it's a separate, target-side check ("which users are allowed
   to be impersonated") distinct from the requester-side `impersonate` scope in step 3.
5. To diagnose a failure, check **Realm settings → Events** (User events) for the
   `TOKEN_EXCHANGE_ERROR` entry and read its `reason` field — it names exactly which of the checks
   above rejected the request.

## Verify

- Cloudflare Access login for an app behind this realm completes and lands the user back at the
  app (confirms the OIDC client from step 1).
- `eq-identity-service` can call the Keycloak admin API and validate a token issued in this realm
  (confirms the client from step 2).
- A bulk-migrated user's login attempt shows "You should receive an email shortly…" and the setup
  email arrives (confirms the flow binding from step 3) — see
  [README.md](README.md#verify) for the full walkthrough.
- Create a user via identity-service's `/users/add` (server-generated temporary password) and
  confirm creation succeeds and the emailed temporary password works — a realm policy stricter
  than `PasswordUtils.PASSWORD_POLICY` will cause Keycloak to reject it at creation time (confirms
  the policy from step 4 doesn't conflict with the generator).
- Trigger the ZTNA client's token-exchange call end-to-end and confirm no `TOKEN_EXCHANGE_ERROR`
  appears in **Realm settings → Events** (confirms step 5's permissions are wired correctly for
  both the audience-exchange and impersonation cases your flow actually uses).
