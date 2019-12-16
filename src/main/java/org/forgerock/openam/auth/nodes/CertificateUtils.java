/*
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.openam.auth.nodes;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Optional;

import javax.security.auth.callback.TextInputCallback;

import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.Strings;

final class CertificateUtils {

    static X509Certificate stringToCert(String certString) throws NodeProcessException {
        try {
            byte[] certDer = Base64.getDecoder().decode(certString);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certDer));
        } catch (CertificateException e) {
            throw new NodeProcessException(e);
        }
    }

    static String certToString(X509Certificate cert) throws NodeProcessException {
        try {
            return new String(Base64.getEncoder().encode(cert.getEncoded()));
        } catch (CertificateEncodingException e) {
            throw new NodeProcessException(e);
        }
    }

    static Optional<String> getValueFromCallbacks(TreeContext context, String attributeName) {
        return context.getCallbacks(TextInputCallback.class).stream()
                .filter(callback -> attributeName.equalsIgnoreCase(callback.getPrompt()))
                .findFirst()
                .map(TextInputCallback::getText)
                .filter(cert -> !Strings.isNullOrEmpty(cert));
    }
}
