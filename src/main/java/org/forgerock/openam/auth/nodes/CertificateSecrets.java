/*
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.openam.auth.nodes;

import static org.forgerock.openam.auth.nodes.CertificateSecretsProvider.CERT_VERIFY_ID;
import static org.forgerock.secrets.Purpose.purpose;

import java.security.PublicKey;
import java.util.Optional;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.secrets.Secrets;
import org.forgerock.secrets.NoSuchSecretException;
import org.forgerock.secrets.SecretsProvider;
import org.forgerock.secrets.keys.VerificationKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class CertificateSecrets {
    private final Logger logger = LoggerFactory.getLogger(CertificateSecrets.class);
    private final Secrets secrets;

    @Inject
    public CertificateSecrets(Secrets secrets) {
        this.secrets = secrets;
    }

    Optional<PublicKey> getCertificateVerificationKey(Realm realm) {
        SecretsProvider provider = secrets.getRealmSecrets(realm);
        try {
            return provider.getActiveSecret(purpose(CERT_VERIFY_ID, VerificationKey.class))
                    .getOrThrow().getPublicKey();
        } catch (InterruptedException | NoSuchSecretException e) {
            logger.error("No certificate found in " + CERT_VERIFY_ID, e);
            return Optional.empty();
        }
    }
}
