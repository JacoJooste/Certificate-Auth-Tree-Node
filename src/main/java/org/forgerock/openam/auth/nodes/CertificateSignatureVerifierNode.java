/*
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.openam.auth.nodes;

import static org.forgerock.openam.auth.nodes.CertificateCollectorNode.X509_CERTIFICATE;
import static org.forgerock.openam.auth.nodes.CertificateValidationNode.getX509Certificate;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import javax.inject.Inject;

import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;

@Node.Metadata(
        outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = CertificateSignatureVerifierNode.Config.class
)
public class CertificateSignatureVerifierNode extends AbstractDecisionNode {
    private final Logger logger = LoggerFactory.getLogger(CertificateSignatureVerifierNode.class);
    private final CertificateSecrets secrets;
    private final Realm realm;

    /**
     * Configuration for the node.
     */
    public interface Config {}

    @Inject
    public CertificateSignatureVerifierNode(@Assisted Realm realm, CertificateSecrets secrets) {
        this.realm = realm;
        this.secrets = secrets;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        logger.debug("CertificateSignatureVerifierNode started");
        List<X509Certificate> certs = context.transientState.get(X509_CERTIFICATE).asList(X509Certificate.class);
        X509Certificate certToVerify = getX509Certificate(certs, logger);
        Optional<PublicKey> caKey = secrets.getCertificateVerificationKey(realm);
        if (!caKey.isPresent()) {
            logger.debug("No CA certificate found");
            return Action.goTo(FALSE_OUTCOME_ID).build();
        }
        try {
            // only check the signature for now, but we need to be more thorough
            // (see org.forgerock.openam.oauth2.OpenAMClientRegistration#verifyTlsClientCertificateAuthentication)
            certToVerify.verify(caKey.get());
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            logger.debug("Certificate signature verification failed.", e);
            return Action.goTo(FALSE_OUTCOME_ID).build();
        }
        return Action.goTo(TRUE_OUTCOME_ID).build();
    }
}
