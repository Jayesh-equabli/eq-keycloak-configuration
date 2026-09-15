package com.equabli.keycloak.authenticator;

import com.equabli.keycloak.IdentityServiceConstants;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.LoginActionsService;

import java.util.List;

/**
 * Username/password form for the SSO-migration rollout. Behaves exactly like the built-in
 * {@link UsernamePasswordForm} except when the submitted username resolves to an enabled user that
 * has <em>no password credential</em> — i.e. a user bulk-migrated by the identity-service
 * {@code /users/migrate} API. Such a user could never pass the password form (and so would never
 * reach their UPDATE_PASSWORD / CONFIGURE_TOTP required actions), so instead of the misleading
 * "invalid username or password" error this authenticator:
 * <ol>
 *   <li>generates a Keycloak {@link ExecuteActionsActionToken} link running UPDATE_PASSWORD +
 *       CONFIGURE_TOTP,</li>
 *   <li>asks the identity-service to deliver it as the branded "set up your password" email
 *       (see {@link SetupMailClient}), and</li>
 *   <li>shows the standard "you should receive an email shortly" info page.</li>
 * </ol>
 *
 * <p>A per-user cooldown (attribute {@value #ATTR_SETUP_MAIL_SENT_AT}) stops repeated login
 * attempts from firing an email each time; within the cooldown the info page is shown without
 * re-sending. Override the cooldown with the {@value #ENV_COOLDOWN_SECONDS} env var (seconds).</p>
 */
public class MigratedUserAuthenticator extends UsernamePasswordForm {

    private static final Logger log = Logger.getLogger(MigratedUserAuthenticator.class);

    static final String ATTR_SETUP_MAIL_SENT_AT = "setupMailSentAt";
    static final String ENV_COOLDOWN_SECONDS = IdentityServiceConstants.ENV_SETUP_MAIL_COOLDOWN_SECONDS;
    static final int DEFAULT_COOLDOWN_SECONDS = IdentityServiceConstants.DEFAULT_COOLDOWN_SECONDS;

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // Fires when the login form is rendered (GET). If this line never appears in the logs, the
        // authenticator is NOT bound into the browser flow - the built-in Username Password Form is
        // still executing. Rebind the flow (see README) before debugging anything else.
        log.infof("[migrated-auth] authenticate() invoked - realm=%s, flow rendering login form",
                context.getRealm().getName());
        super.authenticate(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String username = formData.getFirst(UserModel.USERNAME);
        log.infof("[migrated-auth] action() invoked - submitted username=%s", username);

        if (username != null && !username.isBlank()) {
            UserModel user = lookupUser(context, username.trim());
            if (user == null) {
                log.infof("[migrated-auth] no user resolved for '%s' - delegating to standard form", username);
            } else {
                boolean enabled = user.isEnabled();
                boolean hasPassword = hasPassword(user);
                log.infof("[migrated-auth] user resolved id=%s username=%s email=%s enabled=%s hasPassword=%s",
                        user.getId(), user.getUsername(), user.getEmail(), enabled, hasPassword);
                if (enabled && !hasPassword) {
                    log.infof("[migrated-auth] passwordless migrated user detected - starting setup-mail flow for %s",
                            user.getUsername());
                    handlePasswordlessUser(context, user);
                    return;
                }
                log.infof("[migrated-auth] user %s is not a passwordless-migrated case (enabled=%s hasPassword=%s) "
                        + "- delegating to standard form", user.getUsername(), enabled, hasPassword);
            }
        } else {
            log.infof("[migrated-auth] blank/missing username in form - delegating to standard form");
        }
        super.action(context);
    }

    private UserModel lookupUser(AuthenticationFlowContext context, String username) {
        try {
            return KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username);
        } catch (Exception e) {
            // Duplicate email etc. — let the standard form produce its usual outcome.
            log.debugf(e, "Migrated-user lookup failed for %s", username);
            return null;
        }
    }

    private boolean hasPassword(UserModel user) {
        return user.credentialManager().isConfiguredFor(PasswordCredentialModel.TYPE);
    }

    private void handlePasswordlessUser(AuthenticationFlowContext context, UserModel user) {
        if (user.getEmail() == null || user.getEmail().isBlank()) {
            // Nowhere to send the setup link; fall back to the standard invalid-credentials handling.
            log.warnf("Migrated user %s has no email address - cannot send setup mail", user.getUsername());
            super.action(context);
            return;
        }

        if (isInCooldown(user)) {
            log.infof("Setup mail for %s within cooldown - not re-sending", user.getUsername());
            challengeWithInfo(context, user);
            return;
        }

        try {
            String link = buildActionTokenLink(context, user);
            SetupMailClient.sendSetupMail(context.getRealm(), user.getEmail(), user.getFirstName(), link);
            user.setSingleAttribute(ATTR_SETUP_MAIL_SENT_AT, Long.toString(Time.currentTime()));
        } catch (Exception e) {
            log.errorf(e, "Failed to send password-setup mail for %s", user.getUsername());
            Response challenge = context.form()
                    .setError(Messages.EMAIL_SENT_ERROR)
                    .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
            context.failureChallenge(org.keycloak.authentication.AuthenticationFlowError.INTERNAL_ERROR, challenge);
            return;
        }
        challengeWithInfo(context, user);
    }

    private void challengeWithInfo(AuthenticationFlowContext context, UserModel user) {
        log.infof("Password-setup flow triggered for migrated user %s", user.getUsername());
        Response challenge = context.form()
                .setInfo(Messages.EMAIL_SENT)
                .createInfoPage();
        context.forceChallenge(challenge);
    }

    private boolean isInCooldown(UserModel user) {
        String sentAt = user.getFirstAttribute(ATTR_SETUP_MAIL_SENT_AT);
        if (sentAt == null || sentAt.isBlank()) {
            return false;
        }
        try {
            return Time.currentTime() - Long.parseLong(sentAt) < cooldownSeconds();
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static int cooldownSeconds() {
        String value = System.getenv(ENV_COOLDOWN_SECONDS);
        if (value == null || value.isBlank()) {
            return DEFAULT_COOLDOWN_SECONDS;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return DEFAULT_COOLDOWN_SECONDS;
        }
    }

    /**
     * Builds the same action-token link the admin {@code execute-actions-email} endpoint would:
     * completing it runs UPDATE_PASSWORD then CONFIGURE_TOTP and returns the user to the client
     * they were signing in to.
     */
    private String buildActionTokenLink(AuthenticationFlowContext context, UserModel user) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        int absoluteExpirationInSecs = Time.currentTime() + realm.getActionTokenGeneratedByAdminLifespan();
        List<String> actions = List.of(
                UserModel.RequiredAction.UPDATE_PASSWORD.name(),
                UserModel.RequiredAction.CONFIGURE_TOTP.name());
        String clientId = context.getAuthenticationSession().getClient().getClientId();
        String redirectUri = resolveRedirectUri(realm, user);

        ExecuteActionsActionToken token = new ExecuteActionsActionToken(user.getId(), user.getEmail(),
                absoluteExpirationInSecs, actions, redirectUri, clientId);

        UriInfo uriInfo = session.getContext().getUri();
        UriBuilder builder = LoginActionsService.actionTokenProcessor(uriInfo);
        builder.queryParam("key", token.serialize(session, realm, uriInfo));
        return builder.build(realm.getName()).toString();
    }

    /**
     * Where the user lands once UPDATE_PASSWORD + CONFIGURE_TOTP complete. Each migrated user has a
     * different destination (their client/partner {@code env_instance_url}), which Keycloak cannot
     * validate individually — its <em>Valid redirect URIs</em> allow a trailing {@code *} only on
     * the path, never in the host. So instead of the final per-user URL we point at one stable
     * identity-service forwarder ({@link IdentityServiceConstants#postSetupRedirectUrl()}) carrying
     * the Keycloak user id; that endpoint resolves the real instance URL server-side and 302-redirects
     * to it. Only the single forwarder URL then needs registering on the client.
     *
     * <p>The forwarder base URL is resolved per-realm by {@link IdentityServiceConstants#baseUrl(RealmModel)}
     * (realm attribute, then {@code IDENTITY_SERVICE_BASE_URL}, then
     * {@link IdentityServiceConstants#DEFAULT_BASE_URL}); the static forwarder path is appended by
     * {@link IdentityServiceConstants#postSetupRedirectUrl(RealmModel)}.</p>
     */
    private String resolveRedirectUri(RealmModel realm, UserModel user) {
        String base = IdentityServiceConstants.postSetupRedirectUrl(realm);
        String sep = base.contains("?") ? "&" : "?";
        base = base + sep + "uid=" + user.getId();
        log.infof("redirect uri, userName %s, %s", user.getUsername(), base);
        return base;
    }
}
