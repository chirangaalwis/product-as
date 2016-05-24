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
import org.wso2.appserver.configuration.server.AppServerSecurity;
import org.wso2.appserver.configuration.server.AppServerSingleSignOn;
import org.wso2.appserver.webapp.security.TestConstants;

/**
 * This is a class which defines unit test cases for single-sign-on (SSO) agent configurations.
 *
 * @since 6.0.0
 */
public class SSOAgentConfigurationTest {
    //  TODO: copy JKS file to test resources
    //  TODO: mechanism to validate the happy path

    private static AppServerSingleSignOn getDefaultServerSSOConfiguration() {
        AppServerSingleSignOn configuration = new AppServerSingleSignOn();

        configuration.setIdpURL(TestConstants.DEFAULT_IDP_URL);
        configuration.setIdpEntityId(TestConstants.DEFAULT_IDP_ENTITY_ID);
        configuration.setSignatureValidatorImplClass(TestConstants.DEFAULT_SIGN_VALIDATOR);
        configuration.setIdpCertificateAlias(TestConstants.DEFAULT_IDP_CERT_ALIAS);

        return configuration;
    }

    private static AppServerSecurity getDefaultServerSecurityConfiguration() {
        AppServerSecurity configuration = new AppServerSecurity();

        AppServerSecurity.Keystore keystore = new AppServerSecurity.Keystore();
        keystore.setLocation(TestConstants.DEFAULT_KEY_STORE_LOCATION);
        keystore.setType(TestConstants.DEFAULT_KEY_STORE_TYPE);
        keystore.setPassword(TestConstants.DEFAULT_KEY_STORE_PASSWORD);
        keystore.setKeyAlias(TestConstants.DEFAULT_KEY_ALIAS);
        keystore.setKeyPassword(TestConstants.DEFAULT_KEY_PASSWORD);

        configuration.setKeystore(keystore);

        return configuration;
    }

    private static WebAppSingleSignOn getDefaultWebAppSSOConfiguration() {
        WebAppSingleSignOn configuration = new WebAppSingleSignOn();

        configuration.enableHandlingConsumerURLAfterSLO(true);
        configuration.setQueryParams(TestConstants.DEFAULT_QUERY_PARAMS);
        configuration.setApplicationServerURL(TestConstants.APPLICATION_SERVER_URL_DEFAULT);
        configuration.enableSSO(true);
        configuration.setRequestURLPostfix(TestConstants.DEFAULT_REQUEST_URL_POSTFIX);
        configuration.setHttpBinding(TestConstants.DEFAULT_HTTP_BINDING);
        configuration.setConsumerURLPostfix(TestConstants.DEFAULT_CONSUMER_URL_POSTFIX);
        configuration.setAttributeConsumingServiceIndex(TestConstants.DEFAULT_ATTR_CONSUMING_SERVICE_INDEX);
        configuration.enableSLO(true);
        configuration.setSLOURLPostfix(TestConstants.DEFAULT_SLO_URL_POSTFIX);
        configuration.enableAssertionEncryption(true);
        configuration.enableAssertionSigning(true);
        configuration.enableRequestSigning(true);
        configuration.enableResponseSigning(true);
        configuration.enableForceAuthn(false);
        configuration.enablePassiveAuthn(false);

        return configuration;
    }
}
