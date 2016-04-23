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

import org.apache.catalina.LifecycleException;
import org.apache.catalina.authenticator.SingleSignOn;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.wso2.appserver.configuration.context.AppServerWebAppConfiguration;
import org.wso2.appserver.configuration.context.ContextSSOConfiguration;
import org.wso2.appserver.configuration.listeners.ContextConfigurationLoader;
import org.wso2.appserver.configuration.listeners.ServerConfigurationLoader;
import org.wso2.appserver.configuration.server.ServerSSOConfiguration;

import java.io.IOException;
import java.util.Optional;
import javax.servlet.ServletException;

/**
 * This class implements an Apache Tomcat valve, which performs SAML 2.0 based single-sign-on (SSO) function.
 * <p>
 * This is a sub-class of the {@code org.apache.catalina.authenticator.SingleSignOn} class.
 *
 * @since 6.0.0
 */
public class SAMLSingleSignOn extends SingleSignOn {
    private static final Log log = LogFactory.getLog(SAMLSingleSignOn.class);

    private ServerSSOConfiguration serverConfiguration;
    private ContextSSOConfiguration webappConfiguration;
    private SSOAgentConfiguration agentConfiguration;
    private SSOAgentRequestResolver requestResolver;

    public SAMLSingleSignOn() {
        log.info("Initializing SAML 2.0 based Single-Sign-On valve...");
    }

    /**
     * Retrieves the WSO2 Application Server level configurations.
     *
     * @throws LifecycleException if an error related to the lifecycle occurs
     */
    @Override
    protected void initInternal() throws LifecycleException {
        super.initInternal();
        //  loads the global server level single-sign-on configurations
        serverConfiguration = ServerConfigurationLoader.getServerConfiguration().getSingleSignOnConfiguration();
    }

    /**
     * Performs single-sign-on (SSO) processing for this request using SAML 2.0 protocol.
     * <p>
     * This method overrides the parent {@link SingleSignOn} class' invoke() method.
     *
     * @param request  the servlet request processed
     * @param response the servlet response generated
     * @throws IOException      if an input/output error occurs
     * @throws ServletException if a servlet error occurs
     */
    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        log.info("Invoking SAMLSSOValve. Request URI : " + request.getRequestURI());

        Optional<AppServerWebAppConfiguration> contextConfiguration = ContextConfigurationLoader.
                getContextConfiguration(request.getContext());
        if (contextConfiguration.isPresent()) {
            //  retrieves the configuration instance if exists
            webappConfiguration = contextConfiguration.get().getSingleSignOnConfiguration();
        } else {
            //  invokes next valve and move on to it, if no configuration instance exists
            getNext().invoke(request, response);
            return;
        }

        //  checks if single-sign-on feature is enabled
        if (!webappConfiguration.isSSOEnabled()) {
            if (log.isDebugEnabled()) {
                log.debug("SAML 2.0 single-sign-on not enabled in webapp " + request.getContext().getName());
            }
            //  moves onto the next valve, if single-sign-on is not enabled
            getNext().invoke(request, response);
            return;
        }

        setDefaultConfigurations(webappConfiguration);
        agentConfiguration = (SSOAgentConfiguration) (request.getSessionInternal().getNote(Constants.SSO_AGENT_CONFIG));
        if (agentConfiguration == null) {
            try {
                agentConfiguration = createSSOAgentConfiguration(request.getContextPath());
                request.getSessionInternal().setNote(Constants.SSO_AGENT_CONFIG, agentConfiguration);
            } catch (SSOException e) {
                log.info("Error when initializing the SAML 2.0 single-sign-on agent configurations", e);
                return;
            }
        }

        requestResolver = new SSOAgentRequestResolver(request, agentConfiguration);
        //  if the request URL matches one of the URL(s) to skip, moves on to the next valve
        if (requestResolver.isURLToSkip()) {
            log.info("Request matched a skip URL. Skipping...");
            getNext().invoke(request, response);
            return;
        }

        try {
            if ((requestResolver.isSAML2SSOURL()) || (request.getSession(false) == null) || (
                    request.getSession(false).getAttribute(Constants.SESSION_BEAN) == null)) {
                handleUnauthenticatedRequest(request, response);
            }
        } catch (SSOException e) {
            log.error("An error has occurred when processing the request", e);
            //TODO: consider throws
            getNext().invoke(request, response);
        }

        //  moves onto the next valve
        getNext().invoke(request, response);
    }

    /**
     * Sets default configuration values to chosen configurations, if not set.
     *
     * @param configuration the context level SSO configurations
     */
    private void setDefaultConfigurations(ContextSSOConfiguration configuration) {
        Optional.ofNullable(configuration).ifPresent(context -> {
            context.setApplicationServerURL(Optional.ofNullable(context.getApplicationServerURL()).
                    orElse(Constants.APPLICATION_SERVER_URL_DEFAULT));
            context.setConsumerURLPostfix(Optional.ofNullable(context.getConsumerURLPostfix()).
                    orElse(Constants.CONSUMER_URL_POSTFIX_DEFAULT));
        });
    }

    /**
     * Creates an {@code SSOAgentConfiguration} instance based on the configurations specified.
     *
     * @param contextPath the context path of the processing {@link Request}
     * @return the created {@link SSOAgentConfiguration}
     * @throws SSOException if an error occurs when creating and validating the {@link SSOAgentConfiguration} instance
     */
    private SSOAgentConfiguration createSSOAgentConfiguration(String contextPath) throws SSOException {
        SSOAgentConfiguration ssoAgentConfiguration = new SSOAgentConfiguration();
        ssoAgentConfiguration.initialize(serverConfiguration, webappConfiguration);

        //TODO: SSOX509Credentials

        ssoAgentConfiguration.getSAML2().setSPEntityId(Optional.ofNullable(ssoAgentConfiguration.getSAML2().
                getSPEntityId()).orElse(SSOUtils.generateIssuerID(contextPath).get()));
        ssoAgentConfiguration.getSAML2().setACSURL(Optional.ofNullable(ssoAgentConfiguration.getSAML2().getACSURL()).
                orElse(SSOUtils.generateConsumerURL(contextPath, webappConfiguration).get()));

        ssoAgentConfiguration.validate();
        return ssoAgentConfiguration;
    }

    /**
     * Handles the unauthenticated requests for all contexts.
     *
     * @param request  the servlet request processed
     * @param response the servlet response generated
     * @throws SSOException if an error occurs when handling an unauthenticated request
     */
    private void handleUnauthenticatedRequest(Request request, Response response) throws SSOException {
        SAMLSSOManager manager = new SAMLSSOManager(agentConfiguration);
        String relayStateId = SSOUtils.createID();
        RelayState relayState = SSOUtils.generateRelayState(request);
        agentConfiguration.getSAML2().setRelayState(relayStateId);
        Optional.ofNullable(request.getSession(false)).
                ifPresent(httpSession -> httpSession.setAttribute(relayStateId, relayState));

        agentConfiguration.getSAML2().enablePassiveAuthenticationEnabled(false);
        if (requestResolver.isHttpPOSTBinding()) {
            String htmlPayload = manager.handleAuthnRequestForPOSTBinding(request);
            manager.sendCharacterData(response, htmlPayload);
        } else {
            try {
                response.sendRedirect(manager.handleAuthnRequestForRedirectBinding(request));
            } catch (IOException e) {
                throw new SSOException("Error when handling SAML 2.0 HTTP-Redirect binding", e);
            }
        }
    }
}
