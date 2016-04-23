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

import org.opensaml.common.xml.SAMLConstants;

import javax.servlet.http.HttpServletRequest;

/**
 * This class provides an implementation for resolving the type of an intercepted HTTP servlet request by analyzing
 * the single-sign-on (SSO) agent configurations and HTTP servlet request.
 *
 * @since 6.0.0
 */
public class SSOAgentRequestResolver {
    private SSOAgentConfiguration ssoAgentConfiguration;
    private HttpServletRequest request;

    public SSOAgentRequestResolver(HttpServletRequest request, SSOAgentConfiguration ssoAgentConfiguration) {
        this.ssoAgentConfiguration = ssoAgentConfiguration;
        this.request = request;
    }

    /**
     * Returns true if request URI matches the configured URL to send SAML 2.0 single-sign-on (SSO) an Authentication
     * Request, else false.
     *
     * @return true if request URI matches the configured URL to send SAML 2.0 single-sign-on (SSO) an Authentication
     * Request, else false
     */
    public boolean isSAML2SSOURL() {
        return (ssoAgentConfiguration.isSAMLSSOEnabled()) && (request.getRequestURI().
                endsWith(ssoAgentConfiguration.getRequestURLPostfix()));
    }

    /**
     * Returns true if SAML 2.0 binding type is of HTTP POST type, else false.
     *
     * @return true if SAML 2.0 binding type is of HTTP POST type, else false
     */
    public boolean isHttpPOSTBinding() {
        String httpBindingString = ssoAgentConfiguration.getSAML2().getHttpBinding();
        return (httpBindingString != null) && (SAMLConstants.SAML2_POST_BINDING_URI.equals(httpBindingString));
    }

    /**
     * Returns true if the request URI is one of the URI(s) to be skipped as specified by configuration property
     * SkipURIs, else returns false.
     *
     * @return true if the request URI is one of the URI(s) to be skipped as specified by configuration property
     * SkipURIs, else returns false
     */
    public boolean isURLToSkip() {
        return ssoAgentConfiguration.getSkipURIs().contains(request.getRequestURI());
    }
}
