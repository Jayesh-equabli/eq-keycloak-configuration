package com.equabli.keycloak.email;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.email.EmailTemplateProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Registers {@link IdentityServiceEmailTemplateProvider}. Returning a higher {@link #order()} than
 * Keycloak's built-in {@code freemarker} factory (order 0) makes this the default
 * {@link EmailTemplateProvider}, so no {@code --spi-email-template-provider-default} flag is needed.
 */
public class IdentityServiceEmailTemplateProviderFactory implements EmailTemplateProviderFactory {

    public static final String ID = "identity-service-email";

    private static final Logger log = Logger.getLogger(IdentityServiceEmailTemplateProviderFactory.class);

    @Override
    public EmailTemplateProvider create(KeycloakSession session) {
        return new IdentityServiceEmailTemplateProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        // Startup marker so you can confirm from the logs that this jar was picked up, and see the
        // effective callback URL (env override or the built-in default).
        log.infof("IdentityServiceEmailTemplateProviderFactory loaded (id=%s, order=%d, url=%s)",
                ID, order(), IdentityServiceEmailTemplateProvider.resetMailUrl());
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
        return ID;
    }

    @Override
    public int order() {
        // Higher than the default freemarker provider (0) so Keycloak selects this one.
        return 100;
    }
}
