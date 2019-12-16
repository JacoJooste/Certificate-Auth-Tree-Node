/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2019 ForgeRock AS.
 */

package org.forgerock.openam.auth.nodes;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.forgerock.openam.auth.node.api.Action.goTo;
import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.nodes.CertificateCollectorNode.CertificateCollectionMethod.CALLBACK;
import static org.forgerock.openam.auth.nodes.CertificateCollectorNode.CertificateCollectionMethod.HEADER;
import static org.forgerock.openam.auth.nodes.CertificateCollectorNode.CertificateCollectionMethod.REQUEST;
import static org.forgerock.openam.auth.nodes.CertificateUtils.getValueFromCallbacks;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.inject.Inject;
import javax.security.auth.callback.TextInputCallback;

import org.forgerock.guava.common.collect.ListMultimap;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.encode.Base64;

/**
 * Certificate Collector Node
 */
@Node.Metadata(outcomeProvider = CertificateCollectorNode.CertificateCollectorProvider.class,
        configClass = CertificateCollectorNode.Config.class)
public class CertificateCollectorNode implements Node {
    static final String X509_CERTIFICATE = "X509Certificate";

    private static final String BUNDLE = "org/forgerock/openam/auth/nodes/CertificateCollectorNode";
    private final Logger logger = LoggerFactory.getLogger(CertificateCollectorNode.class);
    private final Config config;

    /**
     * Configuration for the node.
     */
    public interface Config {

        @Attribute(order = 100)
        default Set<CertificateCollectionMethod> certificateCollectionMethod() {
            return new HashSet<>(asList(REQUEST, HEADER));
        }

        @Attribute(order = 200)
        String clientCertificateHttpHeaderName();

        @Attribute(order = 300)
        Set<String> trustedRemoteHosts();
    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     */
    @Inject
    public CertificateCollectorNode(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        Set<CertificateCollectionMethod> collectionMethods = config.certificateCollectionMethod();
        if (collectionMethods.contains(REQUEST)) {
            List<X509Certificate> certificates = getCertificatesFromRequest(context);
            if (!certificates.isEmpty()) {
                return certificatesToAction(certificates, context);
            }
        }
        if (collectionMethods.contains(HEADER) && isHostTrusted(config.trustedRemoteHosts(), context.request.clientIp)) {
            Optional<X509Certificate> certificate = getPortalStyleCert(context.request.headers);
            if (certificate.isPresent()) {
                return certificatesToAction(singletonList(certificate.get()), context);
            }
        }
        if (collectionMethods.contains(CALLBACK)) {
            return getCertificateFromCallback(context)
                    .map(x509Certificate -> certificatesToAction(singletonList(x509Certificate), context))
                    .orElseGet(() -> send(new TextInputCallback("certificate")).build());
        }
        logger.debug("Certificate was not successfully collected based on node configuration and client request");
        return goTo(CertificateCollectorOutcome.NOT_COLLECTED.name()).build();
    }

    private Action certificatesToAction(List<X509Certificate> certs, TreeContext context) {
        return goTo(CertificateCollectorOutcome.COLLECTED.name()).replaceTransientState(
                context.transientState.put(X509_CERTIFICATE, JsonValue.json(certs))).build();
    }

    private Optional<X509Certificate> getCertificateFromCallback(TreeContext context) throws NodeProcessException {
        Optional<String> certificate = getValueFromCallbacks(context, "certificate");
        if (!certificate.isPresent()) {
            return Optional.empty();
        }
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return Optional.of((X509Certificate) factory.generateCertificate(
                    new ByteArrayInputStream(certificate.get().getBytes())));
        } catch (CertificateException e) {
            throw new NodeProcessException(e);
        }
    }

    private boolean isHostTrusted(Set<String> trustedRemoteHosts, String clientIp) {
        if (trustedRemoteHosts.size() == 0) {
            logger.debug("All hosts are trusted, return true");
            return true;
        }
        if (trustedRemoteHosts.size() == 1) {
            if (trustedRemoteHosts.contains("any")) {
                logger.debug("All hosts are trusted, return true");
                return true;
            } else if (trustedRemoteHosts.contains("none")) {
                logger.debug("No hosts are trusted, return false");
                return false;
            } else if (trustedRemoteHosts.contains(clientIp)) {
                return true;
            }
        }
        return trustedRemoteHosts.contains(clientIp);
    }

    private List<X509Certificate> getCertificatesFromRequest(TreeContext context) {
        X509Certificate[] allCerts = (X509Certificate[]) context.request.servletRequest.getAttribute(
                "javax.servlet.request.X509Certificate");
        if (null != allCerts && allCerts.length != 0) {
            if (logger.isDebugEnabled()) {
                X509Certificate userCert = allCerts[0];
                logger.debug("X509Certificate: principal is: " +
                                     userCert.getSubjectDN().getName() +
                                     "\nissuer DN:" + userCert.getIssuerDN().getName() +
                                     "\nserial number:" + userCert.getSerialNumber() +
                                     "\nsubject dn:" + userCert.getSubjectDN().getName());
            }
            return Stream.of(allCerts).filter(Objects::nonNull).collect(Collectors.toList());
        }
        return emptyList();
    }

    private Optional<X509Certificate> getPortalStyleCert(ListMultimap<String, String> headers) throws NodeProcessException {
        String cert = null;
        String clientCertificateHttpHeaderName = config.clientCertificateHttpHeaderName();
        if ((clientCertificateHttpHeaderName != null) && (clientCertificateHttpHeaderName.length() > 0)) {
            logger.debug("Checking cert in HTTP header");
            StringTokenizer tok = new StringTokenizer(clientCertificateHttpHeaderName, ",");
            while (tok.hasMoreTokens()) {
                String key = tok.nextToken();

                if (!headers.containsKey(key)) {
                    continue;
                }
                cert = headers.get(key).get(0);
                cert = cert.trim();
                String beginCert = "-----BEGIN CERTIFICATE-----";
                String endCert = "-----END CERTIFICATE-----";
                int idx = cert.indexOf(endCert);
                if (idx != -1) {
                    cert = cert.substring(beginCert.length(), idx);
                    cert = cert.trim();
                }
            }
        }
        logger.debug("Validate cert: " + cert);
        if (cert == null || cert.equals("")) {
            throw new NodeProcessException("Certificate: no cert from HttpServletRequest header");
        }

        byte[] decoded = Base64.decode(cert);
        if (decoded == null) {
            throw new NodeProcessException("CertificateFromParameter decode failed, possibly invalid Base64 input");
        }

        logger.debug("CertificateFactory.getInstance.");
        CertificateFactory cf;
        X509Certificate userCert;
        try {
            cf = CertificateFactory.getInstance("X.509");
            userCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decoded));
        } catch (Exception e) {
            throw new NodeProcessException("CertificateFromParameter(X509Cert)", e);
        }

        if (userCert == null) {
            return Optional.empty();
        }

        if (logger.isDebugEnabled()) {
            logger.debug("X509Certificate: principal is: " +
                                 userCert.getSubjectDN().getName() +
                                 "\nissuer DN:" + userCert.getIssuerDN().getName() +
                                 "\nserial number:" + userCert.getSerialNumber() +
                                 "\nsubject dn:" + userCert.getSubjectDN().getName());
        }
        return Optional.of(userCert);
    }

    public enum CertificateCollectionMethod {
        REQUEST,
        HEADER,
        CALLBACK
    }

    /**
     * The possible outcomes for the CertificateCollectorNode.
     */
    public enum CertificateCollectorOutcome {
        /**
         * Successful authentication.
         */
        COLLECTED,
        /**
         * Authentication failed.
         */
        NOT_COLLECTED
    }

    /**
     * Defines the possible outcomes from this Certificate Collector node.
     */
    public static class CertificateCollectorProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(CertificateCollectorNode.BUNDLE,
                                                                       CertificateCollectorProvider.class
                                                                               .getClassLoader());
            return ImmutableList.of(
                    new Outcome(CertificateCollectorOutcome.COLLECTED.name(), bundle.getString("collectedOutcome")),
                    new Outcome(CertificateCollectorOutcome.NOT_COLLECTED.name(),
                                bundle.getString("notCollectedOutcome")));
        }
    }

}
