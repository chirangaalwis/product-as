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
package org.wso2.appserver.webapp.security.saml;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.authenticator.SingleSignOn;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.wso2.appserver.configuration.context.AppServerWebAppConfiguration;
import org.wso2.appserver.configuration.context.WebAppSingleSignOn;
import org.wso2.appserver.configuration.listeners.ContextConfigurationLoader;
import org.wso2.appserver.configuration.listeners.ServerConfigurationLoader;
import org.wso2.appserver.configuration.server.AppServerSingleSignOn;
import org.wso2.appserver.webapp.security.Constants;
import org.wso2.appserver.webapp.security.agent.SSOAgentConfiguration;
import org.wso2.appserver.webapp.security.agent.SSOAgentRequestResolver;
import org.wso2.appserver.webapp.security.bean.RelayState;
import org.wso2.appserver.webapp.security.utils.SSOException;
import org.wso2.appserver.webapp.security.utils.SSOUtils;

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
    private AppServerSingleSignOn serverConfiguration;
    private WebAppSingleSignOn contextConfiguration;
    private SSOAgentConfiguration agentConfiguration;

    /**
     * Retrieves the WSO2 Application Server level configurations.
     *
     * @throws LifecycleException if an error related to the lifecycle occurs
     */
    @Override
    protected void initInternal() throws LifecycleException {
        super.initInternal();

        containerLog.info("Initializing SAML 2.0 based Single-Sign-On valve...");
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
        containerLog.info("Invoking SAML 2.0 Single-Sign-On valve. Request URI : " + request.getRequestURI());

        Optional<AppServerWebAppConfiguration> contextConfiguration = ContextConfigurationLoader.
                getContextConfiguration(request.getContext());
        if (contextConfiguration.isPresent()) {
            //  retrieves the configuration instance if exists
            this.contextConfiguration = contextConfiguration.get().getSingleSignOnConfiguration();
        } else {
            //  invokes next valve and move on to it, if no configuration instance exists
            if (containerLog.isDebugEnabled()) {
                containerLog.debug("No context level configuration found for " +
                        request.getContext() + ", skipping SAML 2.0 based Single-Sign-On...");
            }
            getNext().invoke(request, response);
            return;
        }

        //  checks if single-sign-on feature is enabled
        if (!this.contextConfiguration.isSSOEnabled()) {
            if (containerLog.isDebugEnabled()) {
                containerLog.info("SAML 2.0 single-sign-on not enabled in web app " + request.getContext().getName() +
                        ", skipping SAML 2.0 based Single-Sign-On...");
            }
            //  moves onto the next valve, if single-sign-on is not enabled
            getNext().invoke(request, response);
            return;
        }

        setDefaultConfigurations(this.contextConfiguration);
        agentConfiguration = (SSOAgentConfiguration) (request.getSessionInternal().getNote(Constants.SSO_AGENT_CONFIG));
        if (agentConfiguration == null) {
            try {
                agentConfiguration = createAgent(request);
                request.getSessionInternal().setNote(Constants.SSO_AGENT_CONFIG, agentConfiguration);
            } catch (SSOException e) {
                containerLog.warn("Error when initializing the SAML 2.0 Single-Sign-On agent", e);
                return;
            }
        }

        SSOAgentRequestResolver requestResolver = new SSOAgentRequestResolver(request, agentConfiguration);
        //  if the request URL matches one of the URL(s) to skip, moves on to the next valve
        if (requestResolver.isURLToSkip()) {
            containerLog.info("Request matched a skip URL. Skipping...");
            getNext().invoke(request, response);
            return;
        }

        try {
            if ((requestResolver.isSAMLAuthRequestURL()) || (request.getSession(false) == null) || (
                    request.getSession(false).getAttribute(Constants.SESSION_BEAN) == null)) {
                handleUnauthenticatedRequest(request, response, requestResolver);
            }
        } catch (SSOException e) {
            containerLog.error("An error has occurred when processing the request", e);
            //TODO: consider throws
            getNext().invoke(request, response);
        }

        //  moves onto the next valve
        getNext().invoke(request, response);
    }

    /**
     * Sets default configuration values to chosen configurations, if not set.
     *
     * @param configuration the context level single-sign-on (SSO) configurations
     */
    private void setDefaultConfigurations(WebAppSingleSignOn configuration) {
        Optional.ofNullable(configuration)
                .ifPresent(context -> {
                    context.setApplicationServerURL(Optional.ofNullable(context.getApplicationServerURL())
                            .orElse(Constants.APPLICATION_SERVER_URL_DEFAULT));
                    context.setConsumerURLPostfix(Optional.ofNullable(context.getConsumerURLPostfix())
                            .orElse(Constants.CONSUMER_URL_POSTFIX_DEFAULT));
                });
    }

    /**
     * Creates a single-sign-on (SSO) agent based on the configurations specified.
     *
     * @param request the {@link Request} instance used to construct the agent
     * @return the created single-sign-on (SSO) agent instance
     * @throws SSOException if an error occurs during the validation of the constructed agent
     */
    private SSOAgentConfiguration createAgent(Request request) throws SSOException {
        SSOAgentConfiguration ssoAgentConfiguration = new SSOAgentConfiguration();
        ssoAgentConfiguration.initialize(serverConfiguration, contextConfiguration);

        //TODO: SSOX509Credentials

        //  retrieves the request context path and the host's web application base
        String contextPath = request.getContextPath();
        String appBase = request.getHost().getAppBase();
        //  generates the service provider entity ID
        String issuerID = SSOUtils.generateIssuerID(contextPath, appBase).orElse("");
        //  generates the SAML 2.0 Assertion Consumer URL
        String consumerURL = SSOUtils.generateConsumerURL(contextPath, contextConfiguration).orElse("");
        ssoAgentConfiguration.getSAML2().setSPEntityId(
                Optional.ofNullable(ssoAgentConfiguration.getSAML2().getSPEntityId())
                        .orElse(issuerID));
        ssoAgentConfiguration.getSAML2().setACSURL(
                Optional.ofNullable(ssoAgentConfiguration.getSAML2().getACSURL())
                        .orElse(consumerURL));

        ssoAgentConfiguration.validate();
        return ssoAgentConfiguration;
    }

    /**
     * Handles the unauthenticated requests for all contexts.
     *
     * @param request         the servlet request processed
     * @param response        the servlet response generated
     * @param requestResolver the {@link SSOAgentRequestResolver} instance
     * @throws SSOException if an error occurs when handling an unauthenticated request
     */
    private void handleUnauthenticatedRequest(Request request, Response response,
            SSOAgentRequestResolver requestResolver) throws SSOException {
        SAMLSSOManager manager = new SAMLSSOManager(agentConfiguration);

        //  handle the generation of the SAML 2.0 RelayState
        String relayStateId = SSOUtils.createID();
        RelayState relayState = SSOUtils.generateRelayState(request);
        if (agentConfiguration != null) {
            agentConfiguration.getSAML2().setRelayState(relayStateId);
        }
        Optional.ofNullable(request.getSession(false))
                .ifPresent(httpSession -> httpSession.setAttribute(relayStateId, relayState));

        //  TODO: check if the isPassive option of wso2as-web.xml can be removed since this is overridden here + usage
        Optional.ofNullable(agentConfiguration)
                .ifPresent(agent -> agent.getSAML2().enablePassiveAuthenticationEnabled(false));
        if (requestResolver.isHttpPOSTBinding()) {
            containerLog.info("Handling the SAML 2.0 Authentication Request for HTTP-POST binding...");
            String htmlPayload = manager.handleAuthnRequestForPOSTBinding(request);
            manager.sendCharacterData(response, htmlPayload);
        } else {
            containerLog.info("Handling the SAML 2.0 Authentication Request for " +
                    agentConfiguration.getSAML2().getHttpBinding() + "...");
            try {
                response.sendRedirect(manager.handleAuthnRequestForRedirectBinding(request));
            } catch (IOException e) {
                throw new SSOException("Error when handling SAML 2.0 HTTP-Redirect binding", e);
            }
        }
    }
}
