package com.equabli.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * Registers {@link MigratedUserAuthenticator}. This authenticator is NOT picked up automatically:
 * an admin must duplicate the realm's browser flow, replace the built-in "Username Password Form"
 * execution with "{@value #DISPLAY_TYPE}", and bind the copy as the realm's browser flow.
 */
public class MigratedUserAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "migrated-user-password-form";
    static final String DISPLAY_TYPE = "Username Password Form (Migration Setup Email)";

    private static final Logger log = Logger.getLogger(MigratedUserAuthenticatorFactory.class);

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    private static final MigratedUserAuthenticator SINGLETON = new MigratedUserAuthenticator();

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        // Startup marker so you can confirm from the logs that this authenticator was picked up,
        // and see the effective setup-mail callback URL (env override or the built-in default).
        log.infof("MigratedUserAuthenticatorFactory loaded (id=%s, setupMailUrl=%s)",
                PROVIDER_ID, SetupMailClient.setupMailUrl());
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
        return PasswordCredentialModel.TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return false;
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
        return "Username/password form that emails migrated (passwordless) users a set-password + "
                + "configure-TOTP link via the Equabli identity-service instead of rejecting the login.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }
}
