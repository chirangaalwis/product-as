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
package org.wso2.appserver.webapp.security;

/**
 * This class defines constants used during the unit tests.
 *
 * @since 6.0.0
 */
public class TestConstants {
    //  constants used to construct Tomcat internal components for unit-tests
    public static final String WEB_APP_BASE = "webapps";
    public static final String CONTEXT_PATH = "/foo-app";
    public static final String DEFAULT_TOMCAT_HOST = "localhost";
    public static final String SSL_PROTOCOL = "https";
    public static final int SSL_PORT = 8443;

    public static final String APPLICATION_SERVER_URL_DEFAULT = SSL_PROTOCOL + "://" + DEFAULT_TOMCAT_HOST + ":" +
            SSL_PORT;
    public static final String DEFAULT_IDP_ENTITY_ID = "localhost";
    public static final String DEFAULT_IDP_URL = SSL_PROTOCOL + "://" + DEFAULT_IDP_ENTITY_ID + ":9443/samlsso";
    public static final String DEFAULT_SIGN_VALIDATOR = "org.wso2.appserver.webapp.security.saml.signature" +
            ".SAMLSignatureValidatorImplementation";
    public static final String DEFAULT_IDP_CERT_ALIAS = "wso2carbon";
    //  TODO: to be changed
    public static final String DEFAULT_KEY_STORE_LOCATION = "${catalina.base}/conf/wso2/wso2carbon.jks";
    public static final String DEFAULT_KEY_STORE_TYPE = "JKS";
    public static final String DEFAULT_KEY_STORE_PASSWORD = "wso2carbon";
    public static final String DEFAULT_KEY_ALIAS = "wso2carbon";
    public static final String DEFAULT_KEY_PASSWORD = "wso2carbon";
    public static final String DEFAULT_QUERY_PARAMS = "tenant=admin&amp;";
    public static final String DEFAULT_REQUEST_URL_POSTFIX = "samlsso";
    public static final String DEFAULT_HTTP_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    public static final String DEFAULT_CONSUMER_URL_POSTFIX = "/acs";
    public static final String DEFAULT_ATTR_CONSUMING_SERVICE_INDEX = "1784849";
    public static final String DEFAULT_SLO_URL_POSTFIX = "logout";

    /**
     * Prevents instantiating this class.
     */
    private TestConstants() {
    }
}
