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
 * This class defines the constants used in the SAML 2.0 single-sign-on (SSO) implementation.
 *
 * @since 6.0.0
 */
public class Constants {
    //  SAML 2.0 single-sign-on (SSO) parameter name constants
    public static final String HTTP_POST_PARAM_SAML_REQUEST = "SAMLRequest";
    public static final String HTTP_POST_PARAM_SAML_RESPONSE = "SAMLResponse";

    //  SSO agent configuration property default values
    //  TODO: try to get the constructed app server URL - by setting the host name and request getConnector port
    public static final String APPLICATION_SERVER_URL_DEFAULT = "https://localhost:8443";
    public static final String CONSUMER_URL_POSTFIX_DEFAULT = "/acs";
    public static final String BINDING_DEFAULT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    public static final String IDP_URL_DEFAULT = "https://localhost:9443/samlsso";
    public static final String IDP_ENTITY_ID_DEFAULT = "localhost";
    public static final String REQUEST_URL_POSTFIX_DEFAULT = "samlsso";
    public static final String SLO_URL_POSTFIX_DEFAULT = "logout";

    //  HTTP servlet request session notes' property name and attribute name constants
    public static final String SSO_AGENT_CONFIG = "SSOAgentConfig";
    //  TODO: check with the place of setting the session bean class and proper naming
    public static final String SESSION_BEAN = "org.wso2.appserver.webapp.security.bean.LoggedInSession";
    public static final String RELAY_STATE_PARAMETER = "RelayState";
    public static final String REDIRECT_PATH_AFTER_SLO = "redirectPathAfterSLO";
    public static final String REQUEST_PARAM_MAP = "REQUEST_PARAM_MAP";

    //  miscellaneous constants
    public static final String UTF8_ENC = "UTF-8";

    /**
     * Prevents instantiating the Constants class.
     */
    private Constants() {
    }
}
