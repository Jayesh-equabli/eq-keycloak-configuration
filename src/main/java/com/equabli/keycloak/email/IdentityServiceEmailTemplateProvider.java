package com.equabli.keycloak.email;

import com.equabli.keycloak.IdentityServiceConstants;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import org.jboss.logging.Logger;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.freemarker.FreeMarkerEmailTemplateProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.services.resources.LoginActionsService;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

/**
 * Routes Keycloak's "Forgot Password?" email through the Equabli identity-service instead of
 * Keycloak's own SMTP sender (Option B). Keycloak still owns the action token and the
 * update-password page; only the branded email delivery is delegated. All other Keycloak emails
 * (verify-email, etc.) keep the default {@link FreeMarkerEmailTemplateProvider} behaviour because
 * only {@link #sendPasswordReset} is overridden.
 *
 * <p>If the requesting user is a migrated (passwordless) user — one that has never set a password —
 * "Forgot Password?" is treated as first-time account setup rather than a reset: the branded
 * <em>"Set up your Equabli account"</em> email is sent (setup-password endpoint, UPDATE_PASSWORD +
 * CONFIGURE_TOTP), mirroring {@code MigratedUserAuthenticator}. Users who already have a password get
 * the normal password-reset email.</p>
 *
 * <p>Configuration — each value is read from an environment variable on the Keycloak process,
 * falling back to a dev default so it works out of the box for local testing:</p>
 * <ul>
 *   <li>base URL (scheme + host) — resolved per-realm by
 *       {@link IdentityServiceConstants#baseUrl(org.keycloak.models.RealmModel)}: the realm's
 *       {@link IdentityServiceConstants#REALM_ATTR_BASE_URL} attribute if set, else
 *       {@code IDENTITY_SERVICE_BASE_URL}, else {@link IdentityServiceConstants#DEFAULT_BASE_URL}.
 *       The reset-mail path is appended by
 *       {@link IdentityServiceConstants#resetMailUrl(org.keycloak.models.RealmModel)}.</li>
 *   <li>{@code IDENTITY_SERVICE_RESET_MAIL_SECRET} — shared secret sent as the {@code X-Internal-Secret}
 *       header; must equal {@code internal.reset-mail-secret} (env {@code INTERNAL_RESET_MAIL_SECRET})
 *       in the identity-service. The {@link #DEFAULT_SECRET} fallback is DEV ONLY — always override
 *       it with the env var in production.</li>
 * </ul>
 */
public class IdentityServiceEmailTemplateProvider extends FreeMarkerEmailTemplateProvider {

    private static final Logger log = Logger.getLogger(IdentityServiceEmailTemplateProvider.class);

    static final String ENV_SECRET = IdentityServiceConstants.ENV_MAIL_SECRET;
    // Client the action token is issued for; its Valid Redirect URIs must allow the forwarder URL.
    // Falls back to the realm name (matches the azp used elsewhere in this setup) when unset.
    static final String ENV_RESET_CLIENT_ID = IdentityServiceConstants.ENV_RESET_CLIENT_ID;

    // DEV ONLY fallback — override via IDENTITY_SERVICE_RESET_MAIL_SECRET in every real environment.
    static final String DEFAULT_SECRET = IdentityServiceConstants.DEFAULT_SECRET;

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    public IdentityServiceEmailTemplateProvider(KeycloakSession session) {
        super(session);
    }

    /** Callback URL: base URL ({@code IDENTITY_SERVICE_BASE_URL} or default) + the reset-mail path. */
    static String resetMailUrl() {
        return IdentityServiceConstants.resetMailUrl();
    }

    /** Shared secret: {@value #ENV_SECRET} env var if set, else {@link #DEFAULT_SECRET}. */
    static String resetMailSecret() {
        return envOrDefault(ENV_SECRET, DEFAULT_SECRET);
    }

    private static String envOrDefault(String envName, String defaultValue) {
        String value = System.getenv(envName);
        return isBlank(value) ? defaultValue : value;
    }

    @Override
    public void sendPasswordReset(String link, long expirationInMinutes) throws EmailException {
        String secret = resetMailSecret();

        // 'user' and 'realm' are protected fields set by Keycloak on the provider before send.
        String email = user != null ? user.getEmail() : null;
        String firstName = user != null ? user.getFirstName() : null;
        if (isBlank(email)) {
            throw new EmailException("Cannot send password reset: user has no email address");
        }

        // A migrated (passwordless) user has never set a password, so hitting "Forgot Password?" is
        // really first-time account setup, not a reset. Route them to the branded "Set up your Equabli
        // account" email (setup-password endpoint) with UPDATE_PASSWORD + CONFIGURE_TOTP, mirroring
        // MigratedUserAuthenticator. Users who already have a password get the normal reset email.
        boolean setup = !hasPassword(user);
        String endpoint = setup ? IdentityServiceConstants.setupMailUrl(realm) : IdentityServiceConstants.resetMailUrl(realm);
        List<String> actions = setup
                ? List.of(UserModel.RequiredAction.UPDATE_PASSWORD.name(),
                          UserModel.RequiredAction.CONFIGURE_TOTP.name())
                : List.of(UserModel.RequiredAction.UPDATE_PASSWORD.name());
        String flow = setup ? "account-setup" : "password-reset";
        log.infof("Forgot-password for %s resolved to %s flow (hasPassword=%s)", email, flow, !setup);

        // Keycloak's default reset-credentials link ('link') carries no custom redirect, so completing
        // it just returns the user to the login page. Instead build an execute-actions link that carries
        // the post-setup redirect to the identity-service forwarder — mirrors
        // MigratedUserAuthenticator.buildActionTokenLink. The forwarder URL must be registered on the
        // client's Valid Redirect URIs or Keycloak rejects the action token with "Invalid redirect uri".
        String actionLink = buildActionTokenLink(expirationInMinutes, actions);

        String payload = "{"
                + "\"email\":\"" + escape(email) + "\","
                + "\"firstName\":\"" + escape(firstName) + "\","
                + "\"link\":\"" + escape(actionLink) + "\""
                + "}";

        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(endpoint))
                    .timeout(Duration.ofSeconds(15))
                    .header("Content-Type", "application/json")
                    .header("X-Internal-Secret", secret)
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();

            HttpResponse<String> resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() / 100 != 2) {
                throw new EmailException("identity-service returned HTTP " + resp.statusCode()
                        + " for " + flow + " email to " + email);
            }
            log.infof("%s email delegated to identity-service for %s", setup ? "Account-setup" : "Password-reset", email);
        } catch (EmailException e) {
            throw e;
        } catch (Exception e) {
            throw new EmailException("Failed to call identity-service for " + flow + " email", e);
        }
    }

    /** Whether the user already has a password credential; false for migrated (passwordless) users. */
    private boolean hasPassword(UserModel u) {
        return u != null && u.credentialManager().isConfiguredFor(PasswordCredentialModel.TYPE);
    }

    /**
     * Builds an {@link ExecuteActionsActionToken} link that runs the given required {@code actions}
     * and, on completion, redirects to the identity-service forwarder
     * ({@link IdentityServiceConstants#postSetupRedirectUrl()}). Counterpart to
     * {@code MigratedUserAuthenticator.buildActionTokenLink}; the caller picks the action list —
     * UPDATE_PASSWORD only for a real reset, UPDATE_PASSWORD + CONFIGURE_TOTP for migrated-user setup.
     */
    private String buildActionTokenLink(long expirationInMinutes, List<String> actions) {
        int absoluteExpirationInSecs = Time.currentTime() + (int) (expirationInMinutes * 60L);
        String clientId = resolveClientId();
        String redirectUri = resolveRedirectUri();

        ExecuteActionsActionToken token = new ExecuteActionsActionToken(user.getId(), user.getEmail(),
                absoluteExpirationInSecs, actions, redirectUri, clientId);

        UriInfo uriInfo = session.getContext().getUri();
        UriBuilder builder = LoginActionsService.actionTokenProcessor(uriInfo);
        builder.queryParam("key", token.serialize(session, realm, uriInfo));
        return builder.build(realm.getName()).toString();
    }

    /**
     * Client the action token is issued for. The reset flow may run outside an authentication session
     * (e.g. admin-triggered), so we prefer the session's client when present and otherwise fall back to
     * {@value #ENV_RESET_CLIENT_ID}, then the realm name. Whatever client this resolves to must have the
     * forwarder URL in its Valid Redirect URIs.
     */
    private String resolveClientId() {
        if (authenticationSession != null && authenticationSession.getClient() != null) {
            return authenticationSession.getClient().getClientId();
        }
        String configured = System.getenv(ENV_RESET_CLIENT_ID);
        return isBlank(configured) ? realm.getName() : configured.trim();
    }

    /** Post-setup/reset landing URL: the shared forwarder base plus this user's Keycloak id. */
    private String resolveRedirectUri() {
        String base = IdentityServiceConstants.postSetupRedirectUrl(realm);
        String sep = base.contains("?") ? "&" : "?";
        String redirectUri = base + sep + "uid=" + user.getId();
        log.infof("Forgot-password redirect uri for %s: %s", user.getUsername(), redirectUri);
        return redirectUri;
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private static String escape(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
