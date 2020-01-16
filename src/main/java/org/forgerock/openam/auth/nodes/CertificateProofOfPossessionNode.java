/*
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.openam.auth.nodes;

import static java.util.Collections.singletonList;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.openam.auth.nodes.CertificateCollectorNode.X509_CERTIFICATE;
import static org.forgerock.openam.auth.nodes.CertificateUtils.getValueFromCallbacks;
import static org.forgerock.openam.auth.nodes.CertificateUtils.stringToCert;
import static org.forgerock.openam.auth.nodes.CertificateValidationNode.getX509Certificate;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import javax.security.auth.callback.TextInputCallback;

import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.identity.shared.encode.Base64;

@Node.Metadata(
        outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = CertificateProofOfPossessionNode.Config.class
)
public class CertificateProofOfPossessionNode extends AbstractDecisionNode {
    private static final String CHALLENGE = "challenge";
    private static final String CHALLENGE_RESPONSE = "challengeResponse";
    // The callbacks require a default text value for AM to parse the response correctly
    private static final String DEFAULT_TEXT = "dummy value";
    private static final String CHALLENGE_KEY = "certificate.pop.challenge";
    private static final SecureRandom RANDOM = new SecureRandom();
    private final Logger logger = LoggerFactory.getLogger(CertificateProofOfPossessionNode.class);

    /**
     * Configuration for the node.
     */
    public interface Config {}

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        logger.debug("CertificateProofOfPossessionNode started");
        Optional<String> challengeResponse = getValueFromCallbacks(context, CHALLENGE_RESPONSE);
        if (!challengeResponse.isPresent()) {
            return sendChallenge(context);
        }
        byte[] challengeBytes = context.sharedState.get(CHALLENGE_KEY).asString().getBytes();
        byte[] challengeResponseBytes = Base64.decode(challengeResponse.get());
        X509Certificate verificationCert = stringToCert(context.sharedState.get(X509_CERTIFICATE).asString());
        boolean verified = false;
        try {
            Signature signature = Signature.getInstance(verificationCert.getSigAlgName());
            signature.initVerify(verificationCert.getPublicKey());
            signature.update(challengeBytes);
            verified = signature.verify(challengeResponseBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            logger.debug("CertificateProofOfPossessionNode : Signature verification failed", e);
        }
        if (!verified) {
            throw new NodeProcessException("invalid signature");
        }
        return Action.goTo(TRUE_OUTCOME_ID).replaceTransientState(
                context.transientState.put(X509_CERTIFICATE, json(singletonList(verificationCert)))).build();
    }

    private Action sendChallenge(TreeContext context) throws NodeProcessException {
        List<X509Certificate> certs = context.transientState.get(X509_CERTIFICATE).asList(X509Certificate.class);
        X509Certificate certificate = getX509Certificate(certs, logger);
        String certPem = CertificateUtils.certToString(certificate);
        String randomChallenge = getRandomString();
        context.sharedState.add(CHALLENGE_KEY, randomChallenge);
        context.sharedState.add(X509_CERTIFICATE, certPem);
        TextInputCallback challengeCallback = new TextInputCallback(CHALLENGE, DEFAULT_TEXT);
        challengeCallback.setText(randomChallenge);
        return Action.send(challengeCallback, new TextInputCallback(CHALLENGE_RESPONSE, DEFAULT_TEXT))
                .replaceSharedState(context.sharedState.copy()).build();
    }

    private String getRandomString() {
        byte[] bytes = new byte[64];
        RANDOM.nextBytes(bytes);
        return Base64.encode(bytes);
    }
}
