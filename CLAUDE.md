# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`keycloak-reset-mail-spi` is a **Keycloak SPI** (Java 17, Maven) that plugs into a Keycloak server to
support the Equabli SSO-migration rollout. It packages two independent providers into one jar:

1. **Reset-mail provider** (`com.equabli.keycloak.email`) — overrides Keycloak's **Forgot Password**
   email so it is rendered and delivered by the Equabli **identity-service** instead of Keycloak's
   built-in SMTP sender. Only `sendPasswordReset` is overridden; all other Keycloak emails keep the
   default `FreeMarkerEmailTemplateProvider` behaviour. It also branches on credential state: a
   migrated (passwordless) user who hits Forgot Password gets the **setup** email instead of a reset
   (see below).
2. **Migrated-user authenticator** (`com.equabli.keycloak.authenticator`) — a drop-in replacement for
   the browser flow's *Username Password Form*. When a bulk-migrated (passwordless) user tries to log
   in, instead of rejecting them it emails a set-password + configure-TOTP link via identity-service.

This SPI is a companion to the `eq-identity-service` microservice, which hosts the callback endpoints
(`/public/user/internal/*`) and the `/public/user/post-setup-redirect` forwarder this SPI calls.

## Commands

Keycloak dependencies are all `provided` (supplied by the server at runtime), so there is nothing to
run locally — the deliverable is the jar. Use a locally installed `mvn`:

```
mvn clean compile          # compile
mvn clean package          # build the deployable jar -> target/keycloak-reset-mail-spi.jar
```

There is no test source tree. There is no `spring-boot:run` / app to launch; verification happens by
deploying the jar into a Keycloak server (see README "Verify").

**Keycloak version pinning:** `<keycloak.version>` in `pom.xml` **must match the exact Keycloak
SERVER version** the jar is deployed to (currently `26.6.2`). A mismatch can cause `NoSuchMethodError`
/ linkage failures at provider load time, not at compile time. Update this property before building
for a server on a different version.

## Deploy

Copy the jar into the Keycloak `providers/` directory and rebuild the server:

```
cp target/keycloak-reset-mail-spi.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build
```

The migrated-user authenticator is **not picked up automatically** — an admin must duplicate the
realm's browser flow, replace the *Username Password Form* execution with *Username Password Form
(Migration Setup Email)*, and bind the copy as the realm's Browser Flow (see README).

## Architecture

### Provider registration (java.util.ServiceLoader)

Keycloak discovers providers via `META-INF/services/` files — **a new provider is invisible until it
is listed here**:

- `META-INF/services/org.keycloak.authentication.AuthenticatorFactory`
  → `com.equabli.keycloak.authenticator.MigratedUserAuthenticatorFactory`
- `META-INF/services/org.keycloak.email.EmailTemplateProviderFactory`
  → `com.equabli.keycloak.email.IdentityServiceEmailTemplateProviderFactory`

Each `*Factory` implements the Keycloak factory interface: `create(session)` returns the provider,
`getId()` is its provider id, and `init()` logs a startup marker (useful to confirm the jar loaded and
to print the effective resolved URL). `IdentityServiceEmailTemplateProviderFactory.order()` returns
`100` — higher than the built-in `freemarker` factory (0) — so Keycloak selects it as the default
`EmailTemplateProvider` without any `--spi-...` flag.

### Configuration — base URL + env vars, NOT a config file

**This is the most important convention.** All hardcoded constants live in one class:
`com.equabli.keycloak.IdentityServiceConstants`. Do not scatter URL literals, env-var names, or
defaults across the provider classes — add/change them there.

- **Only the base URL changes between environments/tenants**, and it is resolved per-realm by
  `IdentityServiceConstants.baseUrl(RealmModel)` in this order: (1) the realm attribute
  `IdentityServiceConstants.REALM_ATTR_BASE_URL` (`identityServiceBaseUrl`, set per-realm via
  `kcadm update realms/<realm> -s 'attributes.identityServiceBaseUrl=...'` or the Admin REST API —
  the admin console has no UI for generic realm attributes, unlike client/user Attributes tabs — for
  when one Keycloak server hosts multiple realms that each need a different identity-service, with
  no restart required), then (2)
  the `IDENTITY_SERVICE_BASE_URL` env var (`IdentityServiceConstants.ENV_BASE_URL`, a server-wide
  default), then (3) `IdentityServiceConstants.DEFAULT_BASE_URL`. All three supply **scheme + host
  only**, e.g. `https://dev.equabli.io`. Call sites with a `RealmModel` in scope should use the
  `(RealmModel)` overloads of `baseUrl()`/`resetMailUrl()`/`setupMailUrl()`/`postSetupRedirectUrl()`;
  the no-arg overloads only exist for factory-startup logging where no realm is available yet.
- The full endpoint URLs are built by appending **static path constants** to the base:
  `resetMailUrl()`, `setupMailUrl()`, `postSetupRedirectUrl()`. Consumers call these helpers rather
  than reading env vars or concatenating paths themselves. `baseUrl()` trims a trailing `/` so paths
  (which start with `/`) join cleanly.
- Other config is also read from env vars (never a properties file, since this runs inside Keycloak):
  `IDENTITY_SERVICE_RESET_MAIL_SECRET` (shared `X-Internal-Secret` header for both mail callbacks),
  `IDENTITY_SERVICE_RESET_CLIENT_ID`, `IDENTITY_SERVICE_SETUP_MAIL_COOLDOWN_SECONDS`.
- Dev fallbacks (`DEFAULT_SECRET`, `DEFAULT_COOLDOWN_SECONDS`) are DEV ONLY — the secret must be
  overridden in every real environment and must equal the identity-service `internal.reset-mail-secret`
  property (env `INTERNAL_RESET_MAIL_SECRET`).

When adding a new identity-service endpoint call: add its static path + a builder helper to
`IdentityServiceConstants`, don't hardcode the URL in the provider.

### The post-setup / post-reset redirect forwarder

Both flows build an `ExecuteActionsActionToken` whose redirect URI must survive Keycloak's *Valid
Redirect URIs* check. Each migrated user's real destination is a different per-tenant host, and
Keycloak only allows a trailing `*` on the **path**, never the host — so per-tenant URLs can't be
registered. Instead the token points at **one stable forwarder** (`postSetupRedirectUrl()` +
`?uid=<keycloakUserId>`); identity-service's `UserPublicController#postSetupRedirect` resolves the
real instance URL server-side and returns a `302`.

Consequences to keep in mind when touching redirect logic:
- The forwarder URL (`IDENTITY_SERVICE_BASE_URL` + fixed path) must be registered — **with** a
  trailing `*` — under the token's `azp` client's *Valid Redirect URIs*, or the action-token page
  fails with `400 Bad Request` (invalid redirect uri).
- Never put a `*` in `IDENTITY_SERVICE_BASE_URL` — it is the real target URL, not a match pattern.
- The setup flow requires UPDATE_PASSWORD + CONFIGURE_TOTP; the reset flow uses UPDATE_PASSWORD only
  (it must not touch the user's existing TOTP). Keep those action lists distinct.

### Forgot-password branches on credential state

`IdentityServiceEmailTemplateProvider.sendPasswordReset` inspects `user.credentialManager()
.isConfiguredFor(PasswordCredentialModel.TYPE)`. A passwordless (migrated) user has never set a
password, so "Forgot Password?" is first-time setup, not a reset — the provider then sends the
**setup-password** email (`setupMailUrl()`, actions UPDATE_PASSWORD + CONFIGURE_TOTP), matching what
`MigratedUserAuthenticator` sends. Users with a password get the reset email (`resetMailUrl()`, action
UPDATE_PASSWORD only). Both paths share `buildActionTokenLink(expiration, actions)` and the same
post-setup redirect forwarder — only the endpoint and action list differ. The branch is automatic;
there is no config flag.

### HTTP calls to identity-service

`SetupMailClient` and `IdentityServiceEmailTemplateProvider` POST `{email, firstName, link}` JSON to
identity-service using the JDK `HttpClient`, with the `X-Internal-Secret` header. JSON is built with a
hand-rolled `escape()` (no Jackson dependency — keep the jar dependency-free beyond `provided` deps).
Any non-2xx response is treated as failure. Do not log full action-token links (they are sensitive);
log a length + prefix preview, as the existing code does.

### Per-user setup-mail cooldown

`MigratedUserAuthenticator` records `setupMailSentAt` (a Keycloak user attribute) and suppresses
re-sending within the cooldown window so repeated login attempts don't fire an email each time.

## Conventions

- **All constants go in `IdentityServiceConstants`** — base URL, static paths, env-var names,
  defaults. No URL literals or env-var name strings inline in provider classes.
- Keycloak deps stay `provided` scope; avoid adding runtime dependencies — the jar should stay thin
  and load cleanly inside the server.
- Startup markers: factory `init()` methods log the resolved URL so a deployed server's logs confirm
  which environment the SPI is pointed at.
- Keep the two providers independent; they share only `IdentityServiceConstants` and the mail secret.
