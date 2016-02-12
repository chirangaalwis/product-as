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
package org.wso2.appserver.utils.bean;

import java.util.*;

/**
 * A class which represents a holder for context level, overridden configurations, if specified by the WSO2 specific
 * configuration file.
 *
 * @since 6.0.0
 */
public class ContextConfiguration {
    /**
     * A nested class which defines single-sign-on (SSO) configuration properties.
     */
    public static class SingleSignOnConfiguration {
        private Set<String> skipURIs;
        private boolean handleConsumerURLAfterSLO;
        private SAML saml;

        /**
         * Prevents instantiating the class from outside the enclosing class.
         */
        private SingleSignOnConfiguration() {
            skipURIs = new HashSet<>();
            saml = new SAML();
        }

        public Set<String> getSkipURIs() {
            return skipURIs;
        }

        public boolean handleConsumerURLAfterSLOEnabled() {
            return handleConsumerURLAfterSLO;
        }

        public SAML getSaml() {
            return saml;
        }

        /**
         * A nested class which defines the SAML specific single-sign-on (SSO) configurations.
         */
        public static class SAML {
            private boolean enableSSO;
            private String idPURL;
            private String idpEntityId;
            private String httpBinding;
            private String attributeConsumingServiceIndex;
            private boolean enableSLO;
            private String consumerURLPostFix;
            private String requestURLPostFix;
            private String sloURLPostFix;
            private boolean enableResponseSigning;
            private boolean enableAssertionSigning;
            private boolean enableAssertionEncryption;
            private boolean enableRequestSigning;
            private String signatureValidatorImplClass;
            private String additionalRequestParams;
            private boolean isForceAuthn;
            private boolean isPassiveAuthn;
            private String keystorePath;
            private String keystorePassword;
            private String idpCertificateAlias;
            private String privateKeyAlias;
            private String privateKeyPassword;

            /**
             * Prevents instantiating the class from outside the enclosing classes.
             */
            private SAML() {
            }

            public boolean isSSOEnabled() {
                return enableSSO;
            }

            public String getIdPURL() {
                return idPURL;
            }

            public String getIdpEntityId() {
                return idpEntityId;
            }

            public String getHttpBinding() {
                return httpBinding;
            }

            public String getAttributeConsumingServiceIndex() {
                return attributeConsumingServiceIndex;
            }

            public boolean isSLOEnabled() {
                return enableSLO;
            }

            public String getConsumerURLPostFix() {
                return consumerURLPostFix;
            }

            public String getRequestURLPostFix() {
                return requestURLPostFix;
            }

            public String getSLOURLPostFix() {
                return sloURLPostFix;
            }

            public boolean isResponseSigningEnabled() {
                return enableResponseSigning;
            }

            public boolean isAssertionSigningEnabled() {
                return enableAssertionSigning;
            }

            public boolean isAssertionEncryptionEnabled() {
                return enableAssertionEncryption;
            }

            public boolean isRequestSigningEnabled() {
                return enableRequestSigning;
            }

            public String getSignatureValidatorImplClass() {
                return signatureValidatorImplClass;
            }

            public String getAdditionalRequestParams() {
                return additionalRequestParams;
            }

            public boolean isForceAuthn() {
                return isForceAuthn;
            }

            public boolean isPassiveAuthn() {
                return isPassiveAuthn;
            }

            public String getKeystorePath() {
                return keystorePath;
            }

            public String getKeystorePassword() {
                return keystorePassword;
            }

            public String getIdpCertificateAlias() {
                return idpCertificateAlias;
            }

            public String getPrivateKeyAlias() {
                return privateKeyAlias;
            }

            public String getPrivateKeyPassword() {
                return privateKeyPassword;
            }
        }
    }

    /**
     * A nested class which defines class loading related configurations.
     */
    public static class ClassLoadingConfiguration {
        private Map<String, List<String>> environments;

        public ClassLoadingConfiguration() {
            this.environments = new HashMap<>();
        }

        public Map<String, List<String>> getEnvironments() {
            return environments;
        }
    }
}
