/*
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.openam.auth.nodes;

import org.forgerock.openam.secrets.SecretIdProvider;

import com.google.common.collect.ImmutableMultimap;
import com.google.common.collect.Multimap;

public class CertificateSecretsProvider implements SecretIdProvider {

    static final String CERT_VERIFY_ID = "certificate.verification.key";

    @Override
    public Multimap<String, String> getGlobalSingletonSecretIds() {
        return ImmutableMultimap.<String, String>builder()
                .putAll("certificate", CERT_VERIFY_ID)
                .build();
    }

    @Override
    public Multimap<String, String> getRealmSingletonSecretIds() {
        return ImmutableMultimap.<String, String>builder()
                .putAll("certificate", CERT_VERIFY_ID)
                .build();
    }
}
