/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.wso2.appserver.webapp.security.agent;

import org.wso2.appserver.configuration.context.WebAppSingleSignOn;
import org.wso2.appserver.configuration.server.AppServerSingleSignOn;
import org.wso2.appserver.webapp.security.Constants;
import org.wso2.appserver.webapp.security.saml.signature.SSOX509Credential;
import org.wso2.appserver.webapp.security.utils.exception.SSOException;
import org.wso2.appserver.webapp.security.utils.SSOUtils;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * This class defines the configuration aspects of the single-sign-on (SSO) agent.
 *
 * @since 6.0.0
 */
public class SSOAgentConfiguration {
    private Boolean isSSOEnabled;
    private String requestURLPostfix;
    private Set<String> skipURIs;
    private Map<String, String[]> queryParameters;
    private SAML2 saml2;

    public SSOAgentConfiguration() {
        queryParameters = new HashMap<>();
        skipURIs = new HashSet<>();
        saml2 = new SAML2();
    }

    public Boolean isSSOEnabled() {
        return isSSOEnabled;
    }

    public String getRequestURLPostfix() {
        return requestURLPostfix;
    }

    public Set<String> getSkipURIs() {
        return skipURIs;
    }

    public Map<String, String[]> getQueryParameters() {
        return queryParameters;
    }

    public SAML2 getSAML2() {
        return saml2;
    }

    public void initialize(AppServerSingleSignOn server, WebAppSingleSignOn context) {
        Optional.ofNullable(context).ifPresent(configuration -> {
            isSSOEnabled = Optional.ofNullable(context.isSSOEnabled()).orElse(false);
            //  add URIs to be skipped, if any
            Optional.ofNullable(configuration.getSkipURIs()).
                    ifPresent(uris -> uris.getSkipURIs().forEach(skipURIs::add));
            requestURLPostfix = Optional.ofNullable(configuration.getRequestURLPostfix()).
                    orElse(Constants.REQUEST_URL_POSTFIX_DEFAULT);

            saml2.spEntityId = configuration.getIssuerId();
            saml2.acsURL = configuration.getConsumerURL();
            saml2.isForceAuthenticationEnabled = Optional.ofNullable(configuration.isForceAuthnEnabled()).orElse(false);
            saml2.isPassiveAuthenticationEnabled = Optional.ofNullable(configuration.isPassiveAuthnEnabled()).
                    orElse(false);
            saml2.httpBinding = Optional.ofNullable(configuration.getHttpBinding()).orElse(Constants.BINDING_DEFAULT);
            saml2.attributeConsumingServiceIndex = configuration.getAttributeConsumingServiceIndex();
            queryParameters = SSOUtils.getSplitQueryParameters(configuration.getQueryParams());

            saml2.isAssertionSigned = Optional.ofNullable(configuration.isAssertionSigningEnabled())
                    .orElse(false);
            saml2.isAssertionEncrypted = Optional.ofNullable(configuration.isAssertionEncryptionEnabled())
                    .orElse(false);
            saml2.isRequestSigned = Optional.ofNullable(configuration.isRequestSigningEnabled())
                    .orElse(false);
            saml2.isResponseSigned = Optional.ofNullable(configuration.isResponseSigningEnabled())
                    .orElse(false);

            saml2.isSLOEnabled = Optional.ofNullable(configuration.isSLOEnabled())
                    .orElse(false);
            saml2.sloURLPostfix = Optional.ofNullable(configuration.getSLOURLPostfix())
                    .orElse(Constants.SLO_URL_POSTFIX_DEFAULT);
        });

        Optional.ofNullable(server).ifPresent(configuration -> {
            saml2.idPURL = Optional.ofNullable(configuration.getIdpURL()).orElse(Constants.IDP_URL_DEFAULT);
            saml2.idPEntityId = Optional.ofNullable(configuration.getIdpEntityId()).
                    orElse(Constants.IDP_ENTITY_ID_DEFAULT);
            if (saml2.isResponseSigned()) {
                saml2.signatureValidatorImplClass = configuration.getSignatureValidatorImplClass();
                if (saml2.signatureValidatorImplClass == null) {
                    //  TODO: logging
//                    logger.log(Level.FINE, "Signature validator implementation class has not been configured");
                }
            }

        });
    }

    public void validate() throws SSOException {
        if (isSSOEnabled) {
            if (requestURLPostfix == null) {
                throw new SSOException("SAML 2.0 Request URL post-fix not configured");
            }

            if (saml2.spEntityId == null) {
                throw new SSOException("SAML 2.0 Request issuer id not configured");
            }

            if (saml2.acsURL == null) {
                throw new SSOException("SAML 2.0 Consumer URL post-fix not configured");
            }

            if (saml2.idPEntityId == null) {
                throw new SSOException("Identity provider entity id not configured");
            }

            if (saml2.idPURL == null) {
                throw new SSOException("Identity provider URL not configured");
            }

            if (saml2.attributeConsumingServiceIndex == null) {
                //  TODO: container logging
                /*if (log.isDebugEnabled()) {
                    log.debug("SAML 2.0 attribute consuming index not configured, no attributes of the subject will "
                            + "be requested");
                }*/
            }

            if (saml2.isSLOEnabled && saml2.sloURLPostfix == null) {
                throw new SSOException("Single Logout enabled, but SLO URL not configured");
            }

            if ((saml2.isAssertionSigned || saml2.isAssertionEncrypted ||
                    saml2.isResponseSigned || saml2.isRequestSigned) && (saml2.ssoX509Credential == null)) {
                //  TODO: container logging
                /*logger.log(Level.FINE,
                        "\'SSOX509Credential\' not configured, defaulting to " + SSOX509Credential.class.getName());*/
            }

            if ((saml2.isAssertionSigned || saml2.isResponseSigned) && (saml2.ssoX509Credential != null
                    && saml2.ssoX509Credential.getEntityCertificate() == null)) {
                throw new SSOException("Public certificate of IdP not configured");
            }

            if ((saml2.isRequestSigned || saml2.isAssertionEncrypted) && (saml2.ssoX509Credential != null
                    && saml2.ssoX509Credential.getPrivateKey() == null)) {
                throw new SSOException("Private key of SP not configured");
            }
        }
    }

    /**
     * A nested class which defines the SAML 2.0 single-sign-on (SSO) configuration properties.
     */
    public static class SAML2 {
        private String httpBinding;
        private String spEntityId;
        private String acsURL;
        private String idPEntityId;
        private String idPURL;
        private String attributeConsumingServiceIndex;
        private Boolean isPassiveAuthenticationEnabled;
        private Boolean isForceAuthenticationEnabled;
        private String relayState;
        private SSOX509Credential ssoX509Credential;
        private Boolean isAssertionSigned;
        private Boolean isAssertionEncrypted;
        private Boolean isResponseSigned;
        private Boolean isRequestSigned;
        private String signatureValidatorImplClass;
        private Boolean isSLOEnabled;
        private String sloURLPostfix;

        public String getHttpBinding() {
            return httpBinding;
        }

        public String getSPEntityId() {
            return spEntityId;
        }

        public void setSPEntityId(String spEntityId) {
            this.spEntityId = spEntityId;
        }

        public String getACSURL() {
            return acsURL;
        }

        public void setACSURL(String acsURL) {
            this.acsURL = acsURL;
        }

        public String getIdPEntityId() {
            return idPEntityId;
        }

        public String getIdPURL() {
            return idPURL;
        }

        public String getAttributeConsumingServiceIndex() {
            return attributeConsumingServiceIndex;
        }

        public Boolean isPassiveAuthenticationEnabled() {
            return isPassiveAuthenticationEnabled;
        }

        public void enablePassiveAuthentication(Boolean isPassiveAuthenticationEnabled) {
            this.isPassiveAuthenticationEnabled = isPassiveAuthenticationEnabled;
        }

        public Boolean isForceAuthenticationEnabled() {
            return isForceAuthenticationEnabled;
        }

        public String getRelayState() {
            return relayState;
        }

        public void setRelayState(String relayState) {
            this.relayState = relayState;
        }

        public SSOX509Credential getSSOX509Credential() {
            return ssoX509Credential;
        }

        public Boolean isAssertionSigned() {
            return isAssertionSigned;
        }

        public Boolean isAssertionEncrypted() {
            return isAssertionEncrypted;
        }

        public Boolean isResponseSigned() {
            return isResponseSigned;
        }

        public Boolean isRequestSigned() {
            return isRequestSigned;
        }

        public String getSignatureValidatorImplClass() {
            return signatureValidatorImplClass;
        }

        public Boolean isSLOEnabled() {
            return isSLOEnabled;
        }

        public String getSLOURLPostfix() {
            return sloURLPostfix;
        }
    }
}
