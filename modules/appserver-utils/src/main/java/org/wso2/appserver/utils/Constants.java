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

import java.util.List;

/**
 * This class defines WSO2 Application Server specific utility constants.
 *
 * @since 6.0.0
 */
public class Constants {

    /**
     * Prevents initiating the Constants class.
     */
    private Constants() {
    }

    //  Environmental variable property name constant
    public static final String CATALINA_BASE = "catalina.base";
    //  File path related constants
    protected static final String TOMCAT_CONFIGURATION_FOLDER_NAME = "conf";
    protected static final String WSO2_CONFIGURATION_FOLDER_NAME = "wso2";
    protected static final String WSO2AS_CONFIG_FILE_NAME = "wso2as-web.xml";

    public static class SingleSignOnConfigurationConstants {
        public static final String SKIP_URIS = "skipURIs";
        public static final String HANDLE_CONSUMER_URL_AFTER_SLO = "handleConsumerURLAfterSLO";
        public static final String APPLICATION_SERVER_URL = "applicationServerURL";
        public static final String APPLICATION_SERVER_URL_DEFAULT = "https://localhost:8443";
        public static final String LOGIN_URL = "loginURL";
        public static final String LOGIN_URL_DEFAULT = "loginURL";

        /**
         * Prevents initiating the SingleSignOnConfigurationConstants nested class.
         */
        private SingleSignOnConfigurationConstants() {
        }

        public static class SAMLConstants {
            public static final String ENABLE_SAML_SSO = "enableSSO";
            public static final String IDP_URL = "idpURL";
            public static final String IDP_URL_DEFAULT = "https://localhost:9443/samlsso";
            public static final String IDP_ENTITY_ID = "idpEntityId";
            public static final String IDP_ENTITY_ID_DEFAULT = "localhost";
            public static final String BINDING_TYPE = "httpBinding";
            public static final String BINDING_TYPE_DEFAULT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
            public static final String ISSUER_ID = "issuerId";
            public static final String ACS_URL = "consumerURL";
            public static final String ENABLE_SLO = "enableSLO";
            public static final String ATT_CONSUMING_SERVICE_INDEX = "attributeConsumingServiceIndex";
            public static final String ATT_CONSUMING_SERVICE_INDEX_DEFAULT = "1701087467";
            public static final String CONSUMER_URL_POSTFIX = "consumerURLPostFix";
            public static final String CONSUMER_URL_POSTFIX_DEFAULT = "/acs";
            public static final String REQUEST_URL_POSTFIX = "requestURLPostFix";
            public static final String REQUEST_URL_POSTFIX_DEFAULT = "samlsso";
            public static final String SLO_URL_POSTFIX = "sloURLPostFix";
            public static final String SLO_URL_POSTFIX_DEFAULT = "logout";
            public static final String ENABLE_ASSERTION_ENCRYPTION = "enableAssertionEncryption";
            public static final String ENABLE_ASSERTION_SIGNING = "enableAssertionSigning";
            public static final String ENABLE_REQUEST_SIGNING = "enableRequestSigning";
            public static final String ENABLE_RESPONSE_SIGNING = "enableResponseSigning";
            public static final String SIGNATURE_VALIDATOR_IMPL_CLASS = "signatureValidatorImplClass";
            public static final String SIGNATURE_VALIDATOR_IMPL_CLASS_DEFAULT =
                    "org.wso2.appserver.webapp.security.sso.saml.signature.SAMLSignatureValidatorImplementation";
            public static final String ADDITIONAL_REQUEST_PARAMETERS = "additionalRequestParams";
            public static final String ADDITIONAL_REQUEST_PARAMETERS_DEFAULT = "&forceAuth=true";
            public static final String FORCE_AUTHN = "isForceAuthn";
            public static final String PASSIVE_AUTHN = "isPassiveAuthn";
            public static final String KEYSTORE_PATH = "keyStorePath";
            public static final String KEYSTORE_PASSWORD = "keyStorePassword";
            public static final String IDP_PUBLIC_CERTIFICATE_ALIAS = "idpCertAlias";
            public static final String SP_PRIVATE_KEY_ALIAS = "privateKeyAlias";
            public static final String SP_PRIVATE_KEY_PASSWORD = "privateKeyPassword";

            /**
             * Prevents initiating the SAMLConstants nested class.
             */
            private SAMLConstants() {
            }
        }

    }
}
