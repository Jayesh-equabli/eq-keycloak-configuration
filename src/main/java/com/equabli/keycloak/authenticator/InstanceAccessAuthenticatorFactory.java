package com.equabli.keycloak.authenticator;

import com.equabli.keycloak.IdentityServiceConstants;
import com.equabli.keycloak.IdentityServiceConstants.InstanceAccessMode;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

/**
 * Registers {@link InstanceAccessAuthenticator}. Like the migrated-user form it is NOT picked up automatically: an
 * admin adds "{@value #DISPLAY_TYPE}" to the realm's browser flow (README) and sets its mode on the execution's
 * config. Deploying the jar therefore changes nothing in any realm until that realm opts in.
 */
public class InstanceAccessAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "equabli-instance-access";
    static final String DISPLAY_TYPE = "Equabli Instance Access Check";

    private static final Logger log = Logger.getLogger(InstanceAccessAuthenticatorFactory.class);

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = List.of(new ProviderConfigProperty(
            IdentityServiceConstants.CONFIG_INSTANCE_ACCESS_MODE,
            "Mode",
            "OFF: skip the check. LOG_ONLY: log users who would be denied but let them in. "
                    + "ENFORCE: refuse users without access to the client's instance.",
            ProviderConfigProperty.LIST_TYPE,
            InstanceAccessMode.OFF.name(),
            Arrays.stream(InstanceAccessMode.values()).map(Enum::name).toArray(String[]::new)));

    private static final InstanceAccessAuthenticator SINGLETON = new InstanceAccessAuthenticator();

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        log.infof("InstanceAccessAuthenticatorFactory loaded (id=%s)", PROVIDER_ID);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return DISPLAY_TYPE;
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Refuses users who have no access to the Equabli client instance served by the Keycloak client "
                + "(client attribute instanceClientIds vs. user attributes instanceClientIds/allInstanceAccess, "
                + "kept in sync by identity-service). Place it after the user is identified, on every path.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }
}
