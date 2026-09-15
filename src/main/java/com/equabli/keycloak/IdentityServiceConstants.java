package com.equabli.keycloak;

import org.jboss.logging.Logger;
import org.keycloak.models.RealmModel;

/**
 * Single source of truth for every hardcoded constant used by this SPI — the identity-service
 * base URL, the static endpoint paths appended to it, the environment-variable override keys, and
 * the shared dev fallbacks.
 *
 * <p><b>Only the base URL changes between environments/tenants.</b> It resolves, in order:</p>
 * <ol>
 *   <li>the {@link #REALM_ATTR_BASE_URL} attribute on the current realm (Admin Console → Realm
 *       Settings → General → Attributes, or via {@code kcadm}) — lets one Keycloak server host
 *       multiple tenants/environments (realms) that each point at a different identity-service;</li>
 *   <li>the {@link #ENV_BASE_URL} env var on the Keycloak process — a server-wide default;</li>
 *   <li>{@link #DEFAULT_BASE_URL} — the dev fallback.</li>
 * </ol>
 * <p>Whichever wins supplies just the scheme + host, e.g. {@code https://dev.equabli.io} —
 * <em>not</em> a full URL. Each endpoint's full URL is then built by appending its static path
 * ({@link #resetMailUrl(RealmModel)}, {@link #setupMailUrl(RealmModel)},
 * {@link #postSetupRedirectUrl(RealmModel)}).</p>
 */
public final class IdentityServiceConstants {

    /**
     * Realm attribute supplying ONLY the base URL (scheme + host) for that realm, e.g.
     * {@code https://dev.equabli.io}. Takes precedence over {@link #ENV_BASE_URL} when set and
     * non-blank. Set via Admin Console → Realm Settings → General → Attributes, or {@code kcadm}.
     */
    public static final String REALM_ATTR_BASE_URL = "identityServiceBaseUrl";
    /**
     * Env var supplying ONLY the base URL (scheme + host), e.g. {@code https://dev.equabli.io}.
     * Server-wide fallback used when a realm has no {@link #REALM_ATTR_BASE_URL} attribute.
     */
    public static final String ENV_BASE_URL = "IDENTITY_SERVICE_BASE_URL";
    /**
     * Default base URL when neither {@link #REALM_ATTR_BASE_URL} nor {@link #ENV_BASE_URL} is set.
     */
    public static final String DEFAULT_BASE_URL = "https://dev2.equabli.io";
    /**
     * Reset-password mail callback path.
     */
    public static final String RESET_MAIL_PATH =
            "/identity-service/api/public/user/internal/reset-password-email";
    /**
     * Setup-password mail callback path (migrated / passwordless users).
     */
    public static final String SETUP_MAIL_PATH =
            "/identity-service/api/public/user/internal/setup-password-email";

    // ---- Static endpoint paths (appended to the base URL) -----------------------------------
    /**
     * Stable forwarder path the user lands on once UPDATE_PASSWORD (+ CONFIGURE_TOTP) completes; it
     * resolves the per-user instance URL by {@code uid} and 302-redirects. Shared by the setup and
     * reset flows.
     */
    public static final String POST_SETUP_REDIRECT_PATH =
            "/identity-service/api/public/user/post-setup-redirect";
    /**
     * Shared secret sent as the {@code X-Internal-Secret} header on the mail callbacks.
     */
    public static final String ENV_MAIL_SECRET = "IDENTITY_SERVICE_RESET_MAIL_SECRET";
    /**
     * Client the reset action token is issued for; falls back to the realm name when unset.
     */
    public static final String ENV_RESET_CLIENT_ID = "IDENTITY_SERVICE_RESET_CLIENT_ID";

    // ---- Other environment-variable override keys -------------------------------------------
    /**
     * Per-user setup-mail cooldown, in seconds.
     */
    public static final String ENV_SETUP_MAIL_COOLDOWN_SECONDS = "IDENTITY_SERVICE_SETUP_MAIL_COOLDOWN_SECONDS";
    /**
     * DEV ONLY shared secret — always override via {@link #ENV_MAIL_SECRET} in real environments.
     */
    public static final String DEFAULT_SECRET = "testing123";
    /**
     * Default setup-mail cooldown when {@link #ENV_SETUP_MAIL_COOLDOWN_SECONDS} is unset.
     */
    public static final int DEFAULT_COOLDOWN_SECONDS = 900;

    // ---- Dev-only fallbacks -----------------------------------------------------------------
    private static final Logger log = Logger.getLogger(IdentityServiceConstants.class);

    private IdentityServiceConstants() {
    }

    // ---- Resolved URLs (base URL + static path) ---------------------------------------------

    /**
     * Base URL with no realm context — {@link #ENV_BASE_URL}, or {@link #DEFAULT_BASE_URL} when
     * unset/blank. Only used where no {@link RealmModel} is available yet (factory startup logging);
     * request-time resolution should use {@link #baseUrl(RealmModel)} so a realm's
     * {@link #REALM_ATTR_BASE_URL} attribute can override it.
     */
    public static String baseUrl() {
        return resolveBaseUrl(null);
    }

    /**
     * Base URL for {@code realm} — its {@link #REALM_ATTR_BASE_URL} attribute if set, else
     * {@link #ENV_BASE_URL}, else {@link #DEFAULT_BASE_URL}. Any trailing {@code '/'} is stripped so
     * callers can append a path that starts with {@code '/'}.
     */
    public static String baseUrl(RealmModel realm) {
        return resolveBaseUrl(realm);
    }

    private static String resolveBaseUrl(RealmModel realm) {
        String realmValue = realm == null ? null : realm.getAttribute(REALM_ATTR_BASE_URL);
        String envValue = System.getenv(ENV_BASE_URL);
        String value = isBlank(realmValue) ? envValue : realmValue;
        String source = !isBlank(realmValue) ? "realm attribute" : !isBlank(envValue) ? "env var" : "default";
        String base = isBlank(value) ? DEFAULT_BASE_URL : value.trim();
        base = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        // Grep this line after setting/changing the realm attribute to confirm which source won.
        log.infof("Base URL resolved for realm %s: %s (source=%s, realmAttr=%s, env=%s)",
                realm == null ? "n/a" : realm.getName(), base, source, realmValue, envValue);
        return base;
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    /**
     * Full reset-password mail callback URL with no realm context. Prefer
     * {@link #resetMailUrl(RealmModel)} at request time.
     */
    public static String resetMailUrl() {
        return baseUrl() + RESET_MAIL_PATH;
    }

    /** Full reset-password mail callback URL: {@link #baseUrl(RealmModel)} + {@link #RESET_MAIL_PATH}. */
    public static String resetMailUrl(RealmModel realm) {
        return baseUrl(realm) + RESET_MAIL_PATH;
    }

    /**
     * Full setup-password mail callback URL with no realm context. Prefer
     * {@link #setupMailUrl(RealmModel)} at request time.
     */
    public static String setupMailUrl() {
        return baseUrl() + SETUP_MAIL_PATH;
    }

    /** Full setup-password mail callback URL: {@link #baseUrl(RealmModel)} + {@link #SETUP_MAIL_PATH}. */
    public static String setupMailUrl(RealmModel realm) {
        return baseUrl(realm) + SETUP_MAIL_PATH;
    }

    /**
     * Full post-setup redirect forwarder URL with no realm context. Prefer
     * {@link #postSetupRedirectUrl(RealmModel)} at request time.
     */
    public static String postSetupRedirectUrl() {
        return baseUrl() + POST_SETUP_REDIRECT_PATH;
    }

    /**
     * Full post-setup redirect forwarder URL: {@link #baseUrl(RealmModel)} +
     * {@link #POST_SETUP_REDIRECT_PATH}.
     */
    public static String postSetupRedirectUrl(RealmModel realm) {
        return baseUrl(realm) + POST_SETUP_REDIRECT_PATH;
    }
}
