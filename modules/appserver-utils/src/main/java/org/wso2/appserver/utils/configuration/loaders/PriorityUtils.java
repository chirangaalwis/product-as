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
package org.wso2.appserver.utils.configuration.loaders;

import org.wso2.appserver.utils.configuration.model.ClassLoadingConfiguration;
import org.wso2.appserver.utils.configuration.model.Configuration;
import org.wso2.appserver.utils.configuration.model.SSOConfiguration;

import java.util.Optional;

/**
 * A Java class which defines the utility functions when prioritizing the configurations to be set.
 *
 * @since 6.0.0
 */
public class PriorityUtils {
    /**
     * Merges the global and context level configurations generating a final, effective set of configurations.
     *
     * @param globalConfiguration the global configurations
     * @param localConfiguration  the context-level configurations
     * @return the resultant group of configurations
     */
    protected static Configuration merge(Configuration globalConfiguration,
            Optional<Configuration> localConfiguration) {
        //  Create the final, effective configuration set
        Configuration effectiveConfiguration = new Configuration();
        effectiveConfiguration.setClassLoadingConfiguration(new ClassLoadingConfiguration());
        effectiveConfiguration.setRestWebServicesConfiguration(new Configuration.RestWebServicesConfiguration());
        effectiveConfiguration.setSingleSignOnConfiguration(new SSOConfiguration());
        effectiveConfiguration.getSingleSignOnConfiguration().setSAML(new SSOConfiguration.SAML());

        if ((globalConfiguration != null) && (localConfiguration.isPresent())) {
            //  single-sign-on configurations
            SSOConfiguration globalSSOConfiguration = globalConfiguration.getSingleSignOnConfiguration();
            SSOConfiguration localSSOConfiguration = localConfiguration.get().getSingleSignOnConfiguration();
            SSOConfiguration effectiveSSOConfiguration = effectiveConfiguration.getSingleSignOnConfiguration();

            prioritizeGloballyEditableSSOConfigurations(globalSSOConfiguration, effectiveSSOConfiguration);
            prioritizeLocallyEditableSSOConfigurations(localSSOConfiguration, effectiveSSOConfiguration);
            prioritizeLocallyOverridableSSOConfigurations(globalSSOConfiguration, localSSOConfiguration,
                    effectiveSSOConfiguration);
        } else if (globalConfiguration != null) {
            //  single-sign-on configurations
            SSOConfiguration globalSSOConfiguration = globalConfiguration.getSingleSignOnConfiguration();
            SSOConfiguration effectiveSSOConfiguration = effectiveConfiguration.getSingleSignOnConfiguration();

            prioritizeGloballyEditableSSOConfigurations(globalSSOConfiguration, effectiveSSOConfiguration);
            prioritizeLocallyOverridableSSOConfigurations(globalSSOConfiguration, null, effectiveSSOConfiguration);
        } else if (localConfiguration.isPresent()) {
            //  single-sign-on configurations
            SSOConfiguration localSSOConfiguration = localConfiguration.get().getSingleSignOnConfiguration();
            SSOConfiguration effectiveSSOConfiguration = effectiveConfiguration.getSingleSignOnConfiguration();

            prioritizeGloballyEditableSSOConfigurations(null, effectiveSSOConfiguration);
            prioritizeLocallyEditableSSOConfigurations(localSSOConfiguration, effectiveSSOConfiguration);
            prioritizeLocallyOverridableSSOConfigurations(null, localSSOConfiguration, effectiveSSOConfiguration);
        } else {
            SSOConfiguration effectiveSSOConfiguration = effectiveConfiguration.getSingleSignOnConfiguration();
            setSSOPropertyDefaults(effectiveSSOConfiguration);
        }

        return effectiveConfiguration;
    }

    /**
     * Prioritizes the final, effective configurations of single-sign-on properties which are only locally editable.
     *
     * @param local     the context configurations
     * @param effective the resultant group of SSO configurations
     */
    protected static void prioritizeLocallyEditableSSOConfigurations(SSOConfiguration local,
            SSOConfiguration effective) {
        if (effective != null) {
            if ((local != null) && (local.getSAML() != null) && (local.getSAML().getIssuerId() != null)) {
                effective.getSAML().setIssuerId(local.getSAML().getIssuerId());
            }

            if ((local != null) && (local.getSAML() != null) && (local.getSAML().getConsumerURL() != null)) {
                effective.getSAML().setConsumerURL(local.getSAML().getConsumerURL());
            }
        }
    }

    /**
     * Prioritizes the final, effective configurations of single-sign-on properties which are only globally editable.
     *
     * @param global    the global configurations
     * @param effective the resultant group of SSO configurations
     */
    protected static void prioritizeGloballyEditableSSOConfigurations(SSOConfiguration global,
            SSOConfiguration effective) {
        if (effective != null) {
            if ((global != null) && (global.getApplicationServerURL() != null)) {
                effective.setApplicationServerURL(global.getApplicationServerURL());
            } else {
                effective.setApplicationServerURL(
                        LoaderConstants.SSOConfigurationConstants.APPLICATION_SERVER_URL_DEFAULT);
            }

            if ((global != null) && (global.getSAML() != null) && (global.getSAML().getIdpURL() != null)) {
                effective.getSAML().setIdpURL(global.getSAML().getIdpURL());
            } else {
                effective.getSAML().setIdpURL(LoaderConstants.SSOConfigurationConstants.SAMLConstants.IDP_URL_DEFAULT);
            }

            if ((global != null) && (global.getSAML() != null) && (global.getSAML().getIdpEntityId() != null)) {
                effective.getSAML().setIdpEntityId(global.getSAML().getIdpEntityId());
            } else {
                effective.getSAML().
                        setIdpEntityId(LoaderConstants.SSOConfigurationConstants.SAMLConstants.IDP_ENTITY_ID_DEFAULT);
            }

            if ((global != null) && (global.getSAML() != null) && (global.getSAML().getRequestURLPostFix() != null)) {
                effective.getSAML().setRequestURLPostFix(global.getSAML().getRequestURLPostFix());
            } else {
                effective.getSAML().setRequestURLPostFix(
                        LoaderConstants.SSOConfigurationConstants.SAMLConstants.REQUEST_URL_POSTFIX_DEFAULT);
            }

            if ((global != null) && (global.getSAML() != null) && (global.getSAML().getSLOURLPostFix() != null)) {
                effective.getSAML().setSLOURLPostFix(global.getSAML().getSLOURLPostFix());
            } else {
                effective.getSAML().setSLOURLPostFix(
                        LoaderConstants.SSOConfigurationConstants.SAMLConstants.SLO_URL_POSTFIX_DEFAULT);
            }

            if ((global != null) && (global.getSAML() != null) && (global.getSAML().getSignatureValidatorImplClass()
                    != null)) {
                effective.getSAML().
                        setSignatureValidatorImplClass(global.getSAML().getSignatureValidatorImplClass());
            } else {
                effective.getSAML().setSignatureValidatorImplClass(
                        LoaderConstants.SSOConfigurationConstants.SAMLConstants.SIGNATURE_VALIDATOR_IMPL_CLASS_DEFAULT);
            }

            if ((global != null) && (global.getSAML() != null) && (global.getSAML().isForceAuthn() != null)) {
                effective.getSAML().setIsForceAuthn(global.getSAML().isForceAuthn());
            } else {
                effective.getSAML().setIsForceAuthn(false);
            }

            if ((global != null) && (global.getSAML() != null) && (global.getSAML().isPassiveAuthn() != null)) {
                effective.getSAML().setIsPassiveAuthn(global.getSAML().isPassiveAuthn());
            } else {
                effective.getSAML().setIsPassiveAuthn(false);
            }

            if ((global != null) && (global.getSAML() != null) && (global.getSAML().getKeystorePath() != null)) {
                effective.getSAML().setKeystorePath(global.getSAML().getKeystorePath());
            }

            if ((global != null) && (global.getSAML() != null) && (global.getSAML().getKeystorePassword() != null)) {
                effective.getSAML().setKeystorePassword(global.getSAML().getKeystorePassword());
            }

            if ((global != null) && (global.getSAML() != null) && (global.getSAML().getIdpCertificateAlias() != null)) {
                effective.getSAML().setIdpCertificateAlias(global.getSAML().getIdpCertificateAlias());
            }

            if ((global != null) && (global.getSAML() != null) && (global.getSAML().getPrivateKeyAlias() != null)) {
                effective.getSAML().setPrivateKeyAlias(global.getSAML().getPrivateKeyAlias());
            }

            if ((global != null) && (global.getSAML() != null) && (global.getSAML().getPrivateKeyPassword() != null)) {
                effective.getSAML().setPrivateKeyPassword(global.getSAML().getKeystorePassword());
            }
        }
    }

    /**
     * Prioritizes the final, effective configurations of both globally editable and locally overridable for
     * single-sign-on properties.
     *
     * @param global    the global configurations
     * @param local     the context configurations
     * @param effective the resultant group of SSO configurations
     */
    protected static void prioritizeLocallyOverridableSSOConfigurations(SSOConfiguration global, SSOConfiguration local,
            SSOConfiguration effective) {
        if (effective != null) {
            if ((global != null) && (local != null)) {
                if (local.getSkipURIs() != null) {
                    effective.setSkipURIs(local.getSkipURIs());
                } else {
                    effective.setSkipURIs(global.getSkipURIs());
                }

                if (local.handleConsumerURLAfterSLO() != null) {
                    effective.setHandleConsumerURLAfterSLO(local.handleConsumerURLAfterSLO());
                } else {
                    effective.setHandleConsumerURLAfterSLO(global.handleConsumerURLAfterSLO());
                }

                if ((local.getSAML() != null) && (local.getSAML().isSAMLSSOEnabled() != null)) {
                    effective.getSAML().setEnableSAMLSSO(local.getSAML().isSAMLSSOEnabled());
                } else {
                    Optional.ofNullable(global.getSAML()).ifPresent(saml -> effective.getSAML().
                            setEnableSAMLSSO(saml.isSAMLSSOEnabled()));
                }

                if ((local.getSAML() != null) && (local.getSAML().getHttpBinding() != null)) {
                    effective.getSAML().setHttpBinding(local.getSAML().getHttpBinding());
                } else {
                    Optional.ofNullable(global.getSAML()).
                            ifPresent(saml -> effective.getSAML().setHttpBinding(saml.getHttpBinding()));
                }

                if ((local.getSAML() != null) && (local.getSAML().getHttpBinding() != null)) {
                    effective.getSAML().
                            setAttributeConsumingServiceIndex(local.getSAML().getAttributeConsumingServiceIndex());
                } else {
                    Optional.ofNullable(global.getSAML()).ifPresent(saml -> effective.getSAML().
                            setAttributeConsumingServiceIndex(saml.getAttributeConsumingServiceIndex()));
                }

                if ((local.getSAML() != null) && (local.getSAML().isSLOEnabled() != null)) {
                    effective.getSAML().setEnableSLO(local.getSAML().isSLOEnabled());
                } else {
                    Optional.ofNullable(global.getSAML()).ifPresent(saml -> effective.getSAML().
                            setEnableSLO(saml.isSLOEnabled()));
                }

                if ((local.getSAML() != null) && (local.getSAML().isSLOEnabled() != null)) {
                    effective.getSAML().setConsumerURLPostFix(local.getSAML().getConsumerURLPostFix());
                } else {
                    Optional.ofNullable(global.getSAML()).ifPresent(saml -> effective.getSAML().
                            setConsumerURLPostFix(saml.getConsumerURLPostFix()));
                }

                if ((local.getSAML() != null) && (local.getSAML().isAssertionEncryptionEnabled() != null)) {
                    effective.getSAML().
                            setEnableAssertionEncryption(local.getSAML().isAssertionEncryptionEnabled());
                } else {
                    Optional.ofNullable(global.getSAML()).ifPresent(saml -> effective.getSAML().
                            setEnableAssertionEncryption(saml.isAssertionEncryptionEnabled()));
                }

                if ((local.getSAML() != null) && (local.getSAML().isAssertionSigningEnabled() != null)) {
                    effective.getSAML().
                            setEnableAssertionSigning(local.getSAML().isAssertionSigningEnabled());
                } else {
                    Optional.ofNullable(global.getSAML()).ifPresent(saml -> effective.getSAML().
                            setEnableAssertionSigning(saml.isAssertionSigningEnabled()));
                }

                if ((local.getSAML() != null) && (local.getSAML().isRequestSigningEnabled() != null)) {
                    effective.getSAML().
                            setEnableRequestSigning(local.getSAML().isRequestSigningEnabled());
                } else {
                    Optional.ofNullable(global.getSAML()).ifPresent(saml -> effective.getSAML().
                            setEnableRequestSigning(saml.isRequestSigningEnabled()));
                }

                if ((local.getSAML() != null) && (local.getSAML().isResponseSigningEnabled() != null)) {
                    effective.getSAML().
                            setEnableResponseSigning(local.getSAML().isResponseSigningEnabled());
                } else {
                    Optional.ofNullable(global.getSAML()).ifPresent(saml -> effective.getSAML().
                            setEnableResponseSigning(saml.isResponseSigningEnabled()));
                }

                if ((local.getSAML() != null) && (local.getSAML().getAdditionalRequestParams() != null)) {
                    effective.getSAML().
                            setAdditionalRequestParams(local.getSAML().getAdditionalRequestParams());
                } else {
                    Optional.ofNullable(global.getSAML()).ifPresent(saml -> effective.getSAML().
                            setAdditionalRequestParams(saml.getAdditionalRequestParams()));
                }
            } else if (global != null) {
                effective.setSkipURIs(global.getSkipURIs());
                effective.setHandleConsumerURLAfterSLO(global.handleConsumerURLAfterSLO());

                Optional.ofNullable(global.getSAML()).
                        ifPresent(saml -> effective.getSAML().setEnableSAMLSSO(saml.isSAMLSSOEnabled()));
                Optional.ofNullable(global.getSAML()).
                        ifPresent(saml -> effective.getSAML().setHttpBinding(saml.getHttpBinding()));
                Optional.ofNullable(global.getSAML()).ifPresent(saml -> effective.getSAML().
                        setAttributeConsumingServiceIndex(saml.getAttributeConsumingServiceIndex()));
                Optional.ofNullable(global.getSAML()).ifPresent(saml -> effective.getSAML().
                        setEnableSLO(saml.isSLOEnabled()));
                Optional.ofNullable(global.getSAML()).ifPresent(saml -> effective.getSAML().
                        setConsumerURLPostFix(saml.getConsumerURLPostFix()));
                Optional.ofNullable(global.getSAML()).ifPresent(saml -> effective.getSAML().
                        setEnableAssertionEncryption(saml.isAssertionEncryptionEnabled()));
                Optional.ofNullable(global.getSAML()).ifPresent(saml -> effective.getSAML().
                        setEnableAssertionSigning(saml.isAssertionSigningEnabled()));
                Optional.ofNullable(global.getSAML()).ifPresent(saml -> effective.getSAML().
                        setEnableRequestSigning(saml.isRequestSigningEnabled()));
                Optional.ofNullable(global.getSAML()).ifPresent(saml -> effective.getSAML().
                        setEnableResponseSigning(saml.isResponseSigningEnabled()));
                Optional.ofNullable(global.getSAML()).ifPresent(saml -> effective.getSAML().
                        setAdditionalRequestParams(saml.getAdditionalRequestParams()));
            } else if (local != null) {
                effective.setSkipURIs(local.getSkipURIs());
                effective.setHandleConsumerURLAfterSLO(local.handleConsumerURLAfterSLO());

                Optional.ofNullable(local.getSAML()).
                        ifPresent(saml -> effective.getSAML().setEnableSAMLSSO(saml.isSAMLSSOEnabled()));
                Optional.ofNullable(local.getSAML()).
                        ifPresent(saml -> effective.getSAML().setHttpBinding(saml.getHttpBinding()));
                Optional.ofNullable(local.getSAML()).ifPresent(saml -> effective.getSAML().
                        setAttributeConsumingServiceIndex(saml.getAttributeConsumingServiceIndex()));
                Optional.ofNullable(local.getSAML()).ifPresent(saml -> effective.getSAML().
                        setEnableSLO(saml.isSLOEnabled()));
                Optional.ofNullable(local.getSAML()).ifPresent(saml -> effective.getSAML().
                        setConsumerURLPostFix(saml.getConsumerURLPostFix()));
                Optional.ofNullable(local.getSAML()).ifPresent(saml -> effective.getSAML().
                        setEnableAssertionEncryption(saml.isAssertionEncryptionEnabled()));
                Optional.ofNullable(local.getSAML()).ifPresent(saml -> effective.getSAML().
                        setEnableAssertionSigning(saml.isAssertionSigningEnabled()));
                Optional.ofNullable(local.getSAML()).ifPresent(saml -> effective.getSAML().
                        setEnableRequestSigning(saml.isRequestSigningEnabled()));
                Optional.ofNullable(local.getSAML()).ifPresent(saml -> effective.getSAML().
                        setEnableResponseSigning(saml.isResponseSigningEnabled()));
                Optional.ofNullable(local.getSAML()).ifPresent(saml -> effective.getSAML().
                        setAdditionalRequestParams(saml.getAdditionalRequestParams()));
            } else {
                effective.setHandleConsumerURLAfterSLO(true);
            }

            //  Set default values if no values are already set
            if (effective.getSAML().isSAMLSSOEnabled() == null) {
                effective.getSAML().setEnableSAMLSSO(true);
            }
            if (effective.getSAML().getHttpBinding() == null) {
                effective.getSAML().
                        setHttpBinding(LoaderConstants.SSOConfigurationConstants.SAMLConstants.BINDING_TYPE_DEFAULT);
            }
            if (effective.getSAML().getAttributeConsumingServiceIndex() == null) {
                effective.getSAML().setAttributeConsumingServiceIndex(
                        LoaderConstants.SSOConfigurationConstants.SAMLConstants.ATTR_CONSUMING_SERVICE_INDEX_DEFAULT);
            }
            if (effective.getSAML().isSLOEnabled() == null) {
                effective.getSAML().setEnableSLO(true);
            }
            if (effective.getSAML().getConsumerURLPostFix() == null) {
                effective.getSAML().setConsumerURLPostFix(
                        LoaderConstants.SSOConfigurationConstants.SAMLConstants.CONSUMER_URL_POSTFIX_DEFAULT);
            }
            if (effective.getSAML().isAssertionEncryptionEnabled() == null) {
                effective.getSAML().setEnableAssertionEncryption(false);
            }
            if (effective.getSAML().isAssertionSigningEnabled() == null) {
                effective.getSAML().setEnableAssertionSigning(true);
            }
            if (effective.getSAML().isRequestSigningEnabled() == null) {
                effective.getSAML().setEnableRequestSigning(true);
            }
            if (effective.getSAML().isResponseSigningEnabled() == null) {
                effective.getSAML().setEnableResponseSigning(true);
            }
            if (effective.getSAML().getAdditionalRequestParams() == null) {
                effective.getSAML().setAdditionalRequestParams(
                        LoaderConstants.SSOConfigurationConstants.SAMLConstants.ADDITIONAL_REQUEST_PARAMETERS_DEFAULT);
            }
        }
    }

    /**
     * Sets default values if neither global nor context-level configurations are defined.
     *
     * @param effective the resultant group of SSO configurations
     */
    protected static void setSSOPropertyDefaults(SSOConfiguration effective) {
        if (effective != null) {
            effective.setHandleConsumerURLAfterSLO(true);
            effective.setApplicationServerURL(LoaderConstants.SSOConfigurationConstants.APPLICATION_SERVER_URL_DEFAULT);
            effective.getSAML().setEnableSAMLSSO(true);
            effective.getSAML().setIdpURL(LoaderConstants.SSOConfigurationConstants.SAMLConstants.IDP_URL_DEFAULT);
            effective.getSAML().
                    setIdpEntityId(LoaderConstants.SSOConfigurationConstants.SAMLConstants.IDP_ENTITY_ID_DEFAULT);
            effective.getSAML().
                    setHttpBinding(LoaderConstants.SSOConfigurationConstants.SAMLConstants.BINDING_TYPE_DEFAULT);
            effective.getSAML().setAttributeConsumingServiceIndex(
                    LoaderConstants.SSOConfigurationConstants.SAMLConstants.ATTR_CONSUMING_SERVICE_INDEX_DEFAULT);
            effective.getSAML().setEnableSLO(true);
            effective.getSAML().setConsumerURLPostFix(
                    LoaderConstants.SSOConfigurationConstants.SAMLConstants.CONSUMER_URL_POSTFIX_DEFAULT);
            effective.getSAML().setRequestURLPostFix(
                    LoaderConstants.SSOConfigurationConstants.SAMLConstants.REQUEST_URL_POSTFIX_DEFAULT);
            effective.getSAML().
                    setSLOURLPostFix(LoaderConstants.SSOConfigurationConstants.SAMLConstants.SLO_URL_POSTFIX_DEFAULT);
            effective.getSAML().setEnableAssertionEncryption(false);
            effective.getSAML().setEnableAssertionSigning(true);
            effective.getSAML().setEnableRequestSigning(true);
            effective.getSAML().setEnableResponseSigning(true);
            effective.getSAML().setSignatureValidatorImplClass(
                    LoaderConstants.SSOConfigurationConstants.SAMLConstants.SIGNATURE_VALIDATOR_IMPL_CLASS_DEFAULT);
            effective.getSAML().setAdditionalRequestParams(
                    LoaderConstants.SSOConfigurationConstants.SAMLConstants.ADDITIONAL_REQUEST_PARAMETERS_DEFAULT);
            effective.getSAML().setIsForceAuthn(false);
            effective.getSAML().setIsPassiveAuthn(false);
        }
    }
}