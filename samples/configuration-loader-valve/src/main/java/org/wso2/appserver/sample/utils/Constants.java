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
package org.wso2.appserver.sample.utils;

/**
 * This class defines constants used within the unit-tests of Application Server Utils module.
 *
 * @since 6.0.0
 */
public class Constants {
    protected static final String CXF_ENV_NAME = "CXF";
    protected static final String CXF_ENV_CLASSPATH = "${catalina.base}/lib/runtimes/cxf/";
    protected static final String SPRING_ENV_NAME = "Spring";

<<<<<<< HEAD
    static final String IDP_URL = "https://localhost:9443/samlsso";
    static final String IDP_ENTITY_ID = "localhost";
    static final String IDP_CERT_ALIAS = "wso2carbon";
    static final String SKIP_URI = "http://www.example.com";
    static final String QUERY_PARAMS = "tenant=admin&dialect=SAML";
    static final String ACS_BASE = "https://localhost:8443";
    static final String SAML_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    static final String ISSUER_ID = "foo-app";
    static final String CONSUMER_URL = "https://localhost:8443/foo-app/acs";
    static final String CONSUMER_URL_POSTFIX = "acs";
    static final String SLO_URL_POSTFIX = "logout";
    static final String LOGIN_URL_KEY = "LoginURL";
    static final String LOGIN_URL_VALUE = "index.jsp";
    static final String RELAY_STATE_KEY = "RelayState";
    static final String RELAY_STATE_VALUE = "index.jsp";
=======
    protected static final String IDP_URL = "https://localhost:9443/samlsso";
    protected static final String IDP_ENTITY_ID = "localhost";
    protected static final String VALIDATOR_CLASS =
            "org.wso2.appserver.webapp.security.signature.SAMLSignatureValidatorImplementation";
    protected static final String IDP_CERT_ALIAS = "wso2carbon";
    protected static final String SKIP_URI = "http://www.example.com";
    protected static final String QUERY_PARAMS = "tenant=admin&dialect=SAML";
    protected static final String APP_SERVER_URL = "https://localhost:8443";
    protected static final String REQUEST_URL_POSTFIX = "samlsso";
    protected static final String SAML_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    protected static final String ISSUER_ID = "foo-app";
    protected static final String CONSUMER_URL = "https://localhost:8443/foo-app/acs";
    protected static final String CONSUMER_URL_POSTFIX = "/acs";
    protected static final String ATTR_CONSUMER_SERVICE_INDEX = "1784849";
    protected static final String SLO_URL_POSTFIX = "logout";
    protected static final String LOGIN_URL_KEY = "LoginURL";
    protected static final String LOGIN_URL_VALUE = "index.jsp";
    protected static final String RELAY_STATE_KEY = "RelayState";
    protected static final String RELAY_STATE_VALUE = "index.jsp";
>>>>>>> parent of 840bb32... Merge branch 'wso2as-6.0.0-code-formatting-changes' into wso2as-6.0.0-revamped-single-sign-on

    protected static final String USERNAME = "admin";
    protected static final String PASSWORD = "admin";
    protected static final String DATA_AGENT_TYPE = "Thrift";
    protected static final String AUTHN_URL = "ssl://127.0.0.1:7711";
    protected static final String PUBLISHER_URL = "tcp://127.0.0.1:7611";
    protected static final String STREAM_ID = "org.wso2.http.stats:1.0.0";

<<<<<<< HEAD
    static final String KEYSTORE_PATH = "${catalina.base}/conf/wso2/wso2carbon.jks";
    static final String TYPE = "JKS";
    static final String KEYSTORE_PASSWORD = "wso2carbon";
    static final String PRIVATE_KEY_ALIAS = "wso2carbon";
    static final String PRIVATE_KEY_PASSWORD = "wso2carbon";
=======
    protected static final String KEYSTORE_PATH = "${catalina.base}/keystore.jks";
    protected static final String TYPE = "JKS";
    protected static final String KEYSTORE_PASSWORD = "wso2carbon";
    protected static final String PRIVATE_KEY_ALIAS = "wso2carbon";
    protected static final String PRIVATE_KEY_PASSWORD = "wso2carbon";
>>>>>>> parent of 840bb32... Merge branch 'wso2as-6.0.0-code-formatting-changes' into wso2as-6.0.0-revamped-single-sign-on

    protected static final String TRUSTSTORE_PATH = "${catalina.base}/conf/wso2/client-truststore.jks";
    protected static final String TRUSTSTORE_PASSWORD = "wso2carbon";

    /**
     * Prevents instantiating this class.
     */
    private Constants() {
    }
}
