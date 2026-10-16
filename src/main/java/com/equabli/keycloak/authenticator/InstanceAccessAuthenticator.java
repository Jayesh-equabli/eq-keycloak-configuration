package com.equabli.keycloak.authenticator;

import com.equabli.keycloak.IdentityServiceConstants;
import com.equabli.keycloak.IdentityServiceConstants.InstanceAccessMode;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Refuses a login when the user has no access to the client instance (tenant site) the Keycloak client serves.
 *
 * <p>The client's {@value IdentityServiceConstants#CLIENT_ATTR_INSTANCE_CLIENT_IDS} attribute lists the
 * {@code data.client.client_id}s it serves; a client without it is not restricted (shared lower-env clients,
 * admin/service clients). The user passes with {@value IdentityServiceConstants#USER_ATTR_ALL_INSTANCE_ACCESS}
 * = {@code true}, or when one of their {@value IdentityServiceConstants#USER_ATTR_INSTANCE_CLIENT_IDS} values is in
 * the client's list. identity-service owns both attributes and keeps them in sync with its database.</p>
 *
 * <p>Product sites: when the client also has {@value IdentityServiceConstants#CLIENT_ATTR_PRODUCT_CODE} (e.g.
 * {@code EC}), the list checked is {@value IdentityServiceConstants#CLIENT_ATTR_PRODUCT_CLIENT_IDS} instead — the
 * clients from {@code instanceClientIds} that subscribe to that product, maintained by identity-service. So a client
 * user reaches the Collect site only while their client subscribes to Collect. An empty or missing list with a
 * product code set denies everyone except {@code allInstanceAccess} users (fail closed).</p>
 *
 * <p>Rollout is per realm through the execution config {@value IdentityServiceConstants#CONFIG_INSTANCE_ACCESS_MODE}
 * ({@link InstanceAccessMode}); no config means {@code OFF}. It must run after the user is identified on
 * <b>every</b> path, including the SSO-cookie path — see the README for the flow layout.</p>
 */
public class InstanceAccessAuthenticator implements Authenticator {

    private static final Logger log = Logger.getLogger(InstanceAccessAuthenticator.class);

    static final String DENIED_MESSAGE = "You don't currently have access to this application. Please contact our Support Team for assistance.";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        InstanceAccessMode mode = mode(context);
        if (mode == InstanceAccessMode.OFF) {
            context.success();
            return;
        }

        RealmModel realm = context.getRealm();
        ClientModel client = context.getAuthenticationSession().getClient();
        UserModel user = context.getUser();
        String productCode = productCodeOf(client);
        Set<String> clientInstances = productCode == null
                ? csvAttribute(client, IdentityServiceConstants.CLIENT_ATTR_INSTANCE_CLIENT_IDS)
                : csvAttribute(client, IdentityServiceConstants.CLIENT_ATTR_PRODUCT_CLIENT_IDS);
        boolean unrestricted = productCode == null && clientInstances.isEmpty();
        if (unrestricted || user == null || hasAccess(user, clientInstances)) {
            context.success();
            return;
        }

        String clientId = IdentityServiceConstants.clientIdOf(client);
        if (mode == InstanceAccessMode.LOG_ONLY) {
            log.warnf("[instance-access] LOG_ONLY would deny realm=%s user=%s client=%s product=%s instances=%s userInstances=%s",
                    realm.getName(), user.getUsername(), clientId, productCode, clientInstances, userInstanceIds(user));
            context.success();
            return;
        }

        log.warnf("[instance-access] denied realm=%s user=%s client=%s product=%s instances=%s userInstances=%s",
                realm.getName(), user.getUsername(), clientId, productCode, clientInstances, userInstanceIds(user));
        context.getEvent().user(user).detail("instance_client_ids", String.join(",", clientInstances))
                .detail("product_code", productCode == null ? "" : productCode)
                .error(Errors.ACCESS_DENIED);
        Response challenge = context.form()
                .setError(DENIED_MESSAGE)
                .createErrorPage(Response.Status.FORBIDDEN);
        context.failure(AuthenticationFlowError.ACCESS_DENIED, challenge);
    }

    private static InstanceAccessMode mode(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        String value = config == null || config.getConfig() == null ? null
                : config.getConfig().get(IdentityServiceConstants.CONFIG_INSTANCE_ACCESS_MODE);
        InstanceAccessMode mode = InstanceAccessMode.from(value);
        if (mode == InstanceAccessMode.OFF && value != null && !value.isBlank()
                && !InstanceAccessMode.OFF.name().equalsIgnoreCase(value.trim())) {
            log.warnf("[instance-access] unknown mode '%s' in realm %s - treated as OFF", value,
                    context.getRealm().getName());
        }
        return mode;
    }

    /** The client's {@code productCode} attribute, {@code null} when unset or blank. */
    private static String productCodeOf(ClientModel client) {
        String value = client == null ? null : client.getAttribute(IdentityServiceConstants.CLIENT_ATTR_PRODUCT_CODE);
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static Set<String> csvAttribute(ClientModel client, String attribute) {
        String value = client == null ? null : client.getAttribute(attribute);
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(id -> !id.isEmpty())
                .collect(Collectors.toSet());
    }

    private static boolean hasAccess(UserModel user, Set<String> clientInstances) {
        if ("true".equalsIgnoreCase(user.getFirstAttribute(IdentityServiceConstants.USER_ATTR_ALL_INSTANCE_ACCESS))) {
            return true;
        }
        return user.getAttributeStream(IdentityServiceConstants.USER_ATTR_INSTANCE_CLIENT_IDS)
                .map(String::trim)
                .anyMatch(clientInstances::contains);
    }

    private static Set<String> userInstanceIds(UserModel user) {
        return user.getAttributeStream(IdentityServiceConstants.USER_ATTR_INSTANCE_CLIENT_IDS)
                .collect(Collectors.toSet());
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // No form of its own; authenticate() always decides.
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // none
    }

    @Override
    public void close() {
        // no-op
    }
}
