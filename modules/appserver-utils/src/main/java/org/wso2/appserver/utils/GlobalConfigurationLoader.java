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
package org.wso2.appserver.utils;

import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;
import org.apache.catalina.Server;
import org.w3c.dom.Document;
import org.wso2.appserver.utils.bean.GlobalConfiguration;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A Java class which acts as a Apache Tomcat Lifecycle listener and loads the content of the global configuration file.
 *
 * @since 6.0.0
 */
public class GlobalConfigurationLoader implements LifecycleListener {
    private static final Logger logger = Logger.getLogger(GlobalConfigurationLoader.class.getName());
    private static GlobalConfiguration globalConfiguration;

    @Override
    public void lifecycleEvent(LifecycleEvent lifecycleEvent) {
        if (Lifecycle.BEFORE_START_EVENT.equals(lifecycleEvent.getType())) {
            Object source = lifecycleEvent.getSource();
            if (source instanceof Server) {
                try {
                    loadConfiguration();
                } catch (AppServerException e) {
                    logger.log(Level.SEVERE, "An error has occurred when loading the WSO2 global configuration data",
                            e);
                }
            }
        }
    }

    public static GlobalConfiguration getGlobalConfiguration() {
        return globalConfiguration;
    }

    private static void loadConfiguration() throws AppServerException {
        Map<String, Object> tempConfigurationHolder = new HashMap<>();
        Document document = ConfigurationUtils.loadDocument(PathUtils.getWSO2GlobalConfigurationFile());

        //  single-sign-on based configurations
        Optional.ofNullable(ConfigurationUtils.
                loadMultipleSingleTypedElements(document, Constants.SingleSignOnConfigurationConstants.SKIP_URI)).
                ifPresent(value -> tempConfigurationHolder.
                        put(Constants.SingleSignOnConfigurationConstants.SKIP_URIS, value));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.HANDLE_CONSUMER_URL_AFTER_SLO, ConfigurationUtils.
                        loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.HANDLE_CONSUMER_URL_AFTER_SLO));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.APPLICATION_SERVER_URL, ConfigurationUtils.
                        loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.APPLICATION_SERVER_URL));
        ConfigurationUtils.
                addKeyValuePairToMap(tempConfigurationHolder, Constants.SingleSignOnConfigurationConstants.LOGIN_URL,
                        ConfigurationUtils.loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.LOGIN_URL));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.ENABLE_SAML_SSO, ConfigurationUtils.
                        loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.SAMLConstants.ENABLE_SAML_SSO));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.IDP_URL, ConfigurationUtils.
                        loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.SAMLConstants.IDP_URL));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.IDP_ENTITY_ID, ConfigurationUtils.
                        loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.SAMLConstants.IDP_ENTITY_ID));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.BINDING_TYPE, ConfigurationUtils.
                        loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.SAMLConstants.BINDING_TYPE));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.ATT_CONSUMING_SERVICE_INDEX,
                ConfigurationUtils.loadSimpleTypeElement(document,
                        Constants.SingleSignOnConfigurationConstants.SAMLConstants.ATT_CONSUMING_SERVICE_INDEX));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.ENABLE_SLO, ConfigurationUtils.
                        loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.SAMLConstants.ENABLE_SLO));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.CONSUMER_URL_POSTFIX, ConfigurationUtils.
                        loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.SAMLConstants.CONSUMER_URL_POSTFIX));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.REQUEST_URL_POSTFIX, ConfigurationUtils.
                        loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.SAMLConstants.REQUEST_URL_POSTFIX));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.SLO_URL_POSTFIX, ConfigurationUtils.
                        loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.SAMLConstants.SLO_URL_POSTFIX));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.ENABLE_ASSERTION_ENCRYPTION,
                ConfigurationUtils.loadSimpleTypeElement(document,
                        Constants.SingleSignOnConfigurationConstants.SAMLConstants.ENABLE_ASSERTION_ENCRYPTION));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.ENABLE_ASSERTION_SIGNING, ConfigurationUtils.
                        loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.SAMLConstants.ENABLE_ASSERTION_SIGNING));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.ENABLE_REQUEST_SIGNING, ConfigurationUtils.
                        loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.SAMLConstants.ENABLE_REQUEST_SIGNING));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.ENABLE_RESPONSE_SIGNING, ConfigurationUtils.
                        loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.SAMLConstants.ENABLE_RESPONSE_SIGNING));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.SIGNATURE_VALIDATOR_IMPL_CLASS,
                ConfigurationUtils.loadSimpleTypeElement(document,
                        Constants.SingleSignOnConfigurationConstants.SAMLConstants.SIGNATURE_VALIDATOR_IMPL_CLASS));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.ADDITIONAL_REQUEST_PARAMETERS,
                ConfigurationUtils.loadSimpleTypeElement(document,
                        Constants.SingleSignOnConfigurationConstants.SAMLConstants.ADDITIONAL_REQUEST_PARAMETERS));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.FORCE_AUTHN, ConfigurationUtils.
                        loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.SAMLConstants.FORCE_AUTHN));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.PASSIVE_AUTHN, ConfigurationUtils.
                        loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.SAMLConstants.PASSIVE_AUTHN));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.KEYSTORE_PATH, ConfigurationUtils.
                        loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.SAMLConstants.KEYSTORE_PATH));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.KEYSTORE_PASSWORD, ConfigurationUtils.
                        loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.SAMLConstants.KEYSTORE_PASSWORD));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.IDP_PUBLIC_CERTIFICATE_ALIAS,
                ConfigurationUtils.loadSimpleTypeElement(document,
                        Constants.SingleSignOnConfigurationConstants.SAMLConstants.IDP_PUBLIC_CERTIFICATE_ALIAS));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.SP_PRIVATE_KEY_ALIAS, ConfigurationUtils.
                        loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.SAMLConstants.SP_PRIVATE_KEY_ALIAS));
        ConfigurationUtils.addKeyValuePairToMap(tempConfigurationHolder,
                Constants.SingleSignOnConfigurationConstants.SAMLConstants.SP_PRIVATE_KEY_PASSWORD, ConfigurationUtils.
                        loadSimpleTypeElement(document,
                                Constants.SingleSignOnConfigurationConstants.SAMLConstants.SP_PRIVATE_KEY_PASSWORD));

        if (globalConfiguration == null) {
            globalConfiguration = new GlobalConfiguration();
            globalConfiguration.initConfiguration(tempConfigurationHolder);
        } else {
            globalConfiguration.initConfiguration(tempConfigurationHolder);
        }
    }
}
