package com.equabli.keycloak.authenticator;

import com.equabli.keycloak.IdentityServiceConstants;
import org.jboss.logging.Logger;
import org.keycloak.models.RealmModel;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Posts the migrated-user "set up your password" email request to the Equabli identity-service,
 * which renders the branded template and delivers the mail. The Keycloak action-token {@code link}
 * is passed through untouched — Keycloak owns the token and the update-password / configure-TOTP
 * pages it leads to.
 *
 * <p>Configuration — each value is read from an environment variable on the Keycloak process,
 * falling back to a dev default so it works out of the box for local testing:</p>
 * <ul>
 *   <li>{@code IDENTITY_SERVICE_BASE_URL} — the base URL (scheme + host) only, e.g.
 *       {@code https://dev.equabli.io}; the setup-mail path is appended by
 *       {@link IdentityServiceConstants#setupMailUrl()}.</li>
 *   <li>{@code IDENTITY_SERVICE_RESET_MAIL_SECRET} — shared secret sent as the {@code X-Internal-Secret}
 *       header (the same secret the reset-mail provider uses); must equal
 *       {@code internal.reset-mail-secret} in the identity-service. The fallback is DEV ONLY —
 *       always override it with the env var in production.</li>
 * </ul>
 */
final class SetupMailClient {

    private static final Logger log = Logger.getLogger(SetupMailClient.class);

    static final String ENV_SECRET = IdentityServiceConstants.ENV_MAIL_SECRET;

    // DEV ONLY fallback — override via IDENTITY_SERVICE_RESET_MAIL_SECRET in every real environment.
    static final String DEFAULT_SECRET = IdentityServiceConstants.DEFAULT_SECRET;

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    private SetupMailClient() {
    }

    /** Setup-mail URL with no realm context; prefer {@link #setupMailUrl(RealmModel)} at request time. */
    static String setupMailUrl() {
        return IdentityServiceConstants.setupMailUrl();
    }

    static String setupMailUrl(RealmModel realm) {
        return IdentityServiceConstants.setupMailUrl(realm);
    }

    static String setupMailSecret() {
        return envOrDefault(ENV_SECRET, DEFAULT_SECRET);
    }

    private static String envOrDefault(String envName, String defaultValue) {
        String value = System.getenv(envName);
        return value == null || value.isBlank() ? defaultValue : value;
    }

    /**
     * Sends the setup mail request; throws on any non-2xx response or transport failure so the
     * caller can decide what to show the user.
     */
    static void sendSetupMail(RealmModel realm, String email, String firstName, String link)
            throws IOException, InterruptedException {
        String url = setupMailUrl(realm);
        String payload = "{"
                + "\"email\":\"" + escape(email) + "\","
                + "\"firstName\":\"" + escape(firstName) + "\","
                + "\"link\":\"" + escape(link) + "\""
                + "}";

        // Link can be long/sensitive; log its length and prefix rather than the whole token.
        String linkPreview = link == null ? "null"
                : (link.length() <= 60 ? link : link.substring(0, 60) + "...(" + link.length() + " chars)");
        log.infof("[migrated-auth] POST setup-mail -> %s (email=%s, firstName=%s, link=%s)",
                url, email, firstName, linkPreview);

        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(15))
                .header("Content-Type", "application/json")
                .header("X-Internal-Secret", setupMailSecret())
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();

        long start = System.currentTimeMillis();
        HttpResponse<String> resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        long elapsed = System.currentTimeMillis() - start;
        log.infof("[migrated-auth] setup-mail response: HTTP %d in %d ms, body=%s",
                resp.statusCode(), elapsed, resp.body());

        if (resp.statusCode() / 100 != 2) {
            throw new IOException("identity-service returned HTTP " + resp.statusCode()
                    + " for password-setup email to " + email + " (body=" + resp.body() + ")");
        }
        log.infof("[migrated-auth] Password-setup email delegated to identity-service for %s", email);
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
