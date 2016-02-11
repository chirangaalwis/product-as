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

import org.wso2.appserver.utils.Constants;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * A class which represents a holder for global, Application Server configurations specified by the WSO2 specific
 * configuration file.
 *
 * @since 6.0.0
 */
public class GlobalConfiguration {
    private static final Logger logger = Logger.getLogger(GlobalConfiguration.class.getName());

    private SingleSignOnConfiguration singleSignOnConfiguration;
    private ClassLoadingConfiguration classLoadingConfiguration;

    public GlobalConfiguration() {
        singleSignOnConfiguration = new SingleSignOnConfiguration();
        classLoadingConfiguration = new ClassLoadingConfiguration();
    }

    public SingleSignOnConfiguration getSingleSignOnConfiguration() {
        return singleSignOnConfiguration;
    }

    public ClassLoadingConfiguration getClassLoadingConfiguration() {
        return classLoadingConfiguration;
    }

    public void initConfiguration(Map<String, String> ssoConfigurations, Map<String, List<String>> environments) {
        Optional.ofNullable(ssoConfigurations).ifPresent(propertyConfigurations -> {
            String uris = propertyConfigurations.
                    getOrDefault(Constants.SingleSignOnConfigurationConstants.SKIP_URIS, null);
            Optional.ofNullable(uris).ifPresent(uriReferences -> Stream.of(uriReferences.split(",")).
                    forEach(singleSignOnConfiguration.skipURIs::add));

            String handleConsumerURLAfterSLOString = propertyConfigurations.
                    getOrDefault(Constants.SingleSignOnConfigurationConstants.HANDLE_CONSUMER_URL_AFTER_SLO, "true");
            singleSignOnConfiguration.handleConsumerURLAfterSLO = Boolean.parseBoolean(handleConsumerURLAfterSLOString);

            singleSignOnConfiguration.applicationServerURL = propertyConfigurations.
                    getOrDefault(Constants.SingleSignOnConfigurationConstants.APPLICATION_SERVER_URL,
                            Constants.SingleSignOnConfigurationConstants.APPLICATION_SERVER_URL_DEFAULT);

            singleSignOnConfiguration.loginURL = propertyConfigurations.
                    getOrDefault(Constants.SingleSignOnConfigurationConstants.LOGIN_URL,
                            Constants.SingleSignOnConfigurationConstants.LOGIN_URL_DEFAULT);

            String isSAMLSSOEnabledString = propertyConfigurations.
                    getOrDefault(Constants.SingleSignOnConfigurationConstants.SAMLConstants.ENABLE_SAML_SSO, "false");
            singleSignOnConfiguration.saml.enableSSO = Boolean.parseBoolean(isSAMLSSOEnabledString);

            singleSignOnConfiguration.saml.idPURL = propertyConfigurations.
                    getOrDefault(Constants.SingleSignOnConfigurationConstants.SAMLConstants.IDP_URL,
                            Constants.SingleSignOnConfigurationConstants.SAMLConstants.IDP_URL_DEFAULT);
            singleSignOnConfiguration.saml.idpEntityId = propertyConfigurations.
                    getOrDefault(Constants.SingleSignOnConfigurationConstants.SAMLConstants.IDP_ENTITY_ID,
                            Constants.SingleSignOnConfigurationConstants.SAMLConstants.IDP_ENTITY_ID_DEFAULT);

            singleSignOnConfiguration.saml.httpBinding = propertyConfigurations.
                    getOrDefault(Constants.SingleSignOnConfigurationConstants.SAMLConstants.BINDING_TYPE,
                            Constants.SingleSignOnConfigurationConstants.SAMLConstants.BINDING_TYPE_DEFAULT);

            singleSignOnConfiguration.saml.attributeConsumingServiceIndex = propertyConfigurations.getOrDefault(
                    Constants.SingleSignOnConfigurationConstants.SAMLConstants.ATT_CONSUMING_SERVICE_INDEX,
                    Constants.SingleSignOnConfigurationConstants.SAMLConstants.ATT_CONSUMING_SERVICE_INDEX_DEFAULT);

            String enableSLOString = propertyConfigurations.
                    getOrDefault(Constants.SingleSignOnConfigurationConstants.SAMLConstants.ENABLE_SLO, "true");
            singleSignOnConfiguration.saml.enableSLO = Boolean.parseBoolean(enableSLOString);

            singleSignOnConfiguration.saml.consumerURLPostFix = propertyConfigurations.
                    getOrDefault(Constants.SingleSignOnConfigurationConstants.SAMLConstants.CONSUMER_URL_POSTFIX,
                            Constants.SingleSignOnConfigurationConstants.SAMLConstants.CONSUMER_URL_POSTFIX_DEFAULT);
            singleSignOnConfiguration.saml.requestURLPostFix = propertyConfigurations.
                    getOrDefault(Constants.SingleSignOnConfigurationConstants.SAMLConstants.REQUEST_URL_POSTFIX,
                            Constants.SingleSignOnConfigurationConstants.SAMLConstants.REQUEST_URL_POSTFIX_DEFAULT);
            singleSignOnConfiguration.saml.sloURLPostFix = propertyConfigurations.
                    getOrDefault(Constants.SingleSignOnConfigurationConstants.SAMLConstants.SLO_URL_POSTFIX,
                            Constants.SingleSignOnConfigurationConstants.SAMLConstants.SLO_URL_POSTFIX_DEFAULT);

            String enableAssertionEncryptionString = propertyConfigurations.getOrDefault(
                    Constants.SingleSignOnConfigurationConstants.SAMLConstants.ENABLE_ASSERTION_ENCRYPTION, "false");
            singleSignOnConfiguration.saml.enableAssertionEncryption = Boolean.
                    parseBoolean(enableAssertionEncryptionString);
            String enableAssertionSigningString = propertyConfigurations.
                    getOrDefault(Constants.SingleSignOnConfigurationConstants.SAMLConstants.ENABLE_ASSERTION_SIGNING,
                            "true");
            singleSignOnConfiguration.saml.enableAssertionSigning = Boolean.parseBoolean(enableAssertionSigningString);
            String enableRequestSigningString = propertyConfigurations.
                    getOrDefault(Constants.SingleSignOnConfigurationConstants.SAMLConstants.ENABLE_REQUEST_SIGNING,
                            "true");
            singleSignOnConfiguration.saml.enableRequestSigning = Boolean.parseBoolean(enableRequestSigningString);
            String enableResponseSigningString = propertyConfigurations.
                    getOrDefault(Constants.SingleSignOnConfigurationConstants.SAMLConstants.ENABLE_RESPONSE_SIGNING,
                            "true");
            singleSignOnConfiguration.saml.enableResponseSigning = Boolean.parseBoolean(enableResponseSigningString);

            singleSignOnConfiguration.saml.signatureValidatorImplClass = propertyConfigurations.getOrDefault(
                    Constants.SingleSignOnConfigurationConstants.SAMLConstants.SIGNATURE_VALIDATOR_IMPL_CLASS,
                    Constants.SingleSignOnConfigurationConstants.SAMLConstants.SIGNATURE_VALIDATOR_IMPL_CLASS_DEFAULT);
            singleSignOnConfiguration.saml.additionalRequestParams = propertyConfigurations.getOrDefault(
                    Constants.SingleSignOnConfigurationConstants.SAMLConstants.ADDITIONAL_REQUEST_PARAMETERS,
                    Constants.SingleSignOnConfigurationConstants.SAMLConstants.ADDITIONAL_REQUEST_PARAMETERS_DEFAULT);

            String enableForceAuthnString = propertyConfigurations
                    .getOrDefault(Constants.SingleSignOnConfigurationConstants.SAMLConstants.FORCE_AUTHN, "false");
            singleSignOnConfiguration.saml.isForceAuthn = Boolean.parseBoolean(enableForceAuthnString);
            String enablePassiveAuthnString = propertyConfigurations
                    .getOrDefault(Constants.SingleSignOnConfigurationConstants.SAMLConstants.PASSIVE_AUTHN, "false");
            singleSignOnConfiguration.saml.isPassiveAuthn = Boolean.parseBoolean(enablePassiveAuthnString);

            singleSignOnConfiguration.saml.keystorePath = propertyConfigurations.
                    getOrDefault(Constants.SingleSignOnConfigurationConstants.SAMLConstants.KEYSTORE_PATH, null);
            singleSignOnConfiguration.saml.keystorePassword = propertyConfigurations.
                    getOrDefault(Constants.SingleSignOnConfigurationConstants.SAMLConstants.KEYSTORE_PASSWORD, null);
            singleSignOnConfiguration.saml.idpCertificateAlias = propertyConfigurations.getOrDefault(
                    Constants.SingleSignOnConfigurationConstants.SAMLConstants.IDP_PUBLIC_CERTIFICATE_ALIAS, null);
            singleSignOnConfiguration.saml.privateKeyAlias = propertyConfigurations.
                    getOrDefault(Constants.SingleSignOnConfigurationConstants.SAMLConstants.SP_PRIVATE_KEY_ALIAS, null);
            singleSignOnConfiguration.saml.privateKeyPassword = propertyConfigurations.
                    getOrDefault(Constants.SingleSignOnConfigurationConstants.SAMLConstants.SP_PRIVATE_KEY_PASSWORD,
                            null);

            Optional.ofNullable(environments).ifPresent(
                    classLoadingEnvironments -> classLoadingEnvironments.entrySet().stream().forEach(
                            entry -> classLoadingConfiguration.environments.put(entry.getKey(), entry.getValue())));
        });
    }

    /**
     * A nested class which defines single-sign-on (SSO) configuration properties.
     */
    public static class SingleSignOnConfiguration {
        private Set<String> skipURIs;
        private String applicationServerURL;
        private boolean handleConsumerURLAfterSLO;
        private String loginURL;
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

        public String getApplicationServerURL() {
            return applicationServerURL;
        }

        public String getLoginURL() {
            return loginURL;
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
