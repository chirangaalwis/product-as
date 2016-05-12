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
import org.wso2.appserver.webapp.security.saml.signature.SSOX509Credential;
import org.wso2.appserver.webapp.security.utils.SSOUtils;
import org.wso2.appserver.webapp.security.utils.exception.SSOException;

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
    private SSOAgentRequestResolver requestResolver;

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
     * Performs single-sign-on(SSO) or single-logout(SLO) processing based on the request, using SAML 2.0.
     * SAML 2.0 Web Browser SSO and SAML 2.0 Single Logout Profiles are used for single-sign-on and single-logout,
     * respectively.
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
        containerLog.info("Invoking SAML 2.0 single-sign-on valve. Request URI : " + request.getRequestURI());

        Optional<AppServerWebAppConfiguration> contextConfiguration = ContextConfigurationLoader.
                getContextConfiguration(request.getContext());
        if (contextConfiguration.isPresent()) {
            //  retrieves the configuration instance if exists
            this.contextConfiguration = contextConfiguration.get().getSingleSignOnConfiguration();
            if (this.contextConfiguration == null) {
                if (containerLog.isDebugEnabled()) {
                    containerLog.debug("No context level, single-sign-on configuration found for " +
                            request.getContext() + ", skipping SAML 2.0 based single-sign-on/single-logout...");
                }
                getNext().invoke(request, response);
                return;
            }
        } else {
            //  invokes next valve and moves on to it, if no configuration instance exists
            if (containerLog.isDebugEnabled()) {
                containerLog.debug("No context level configuration found for " +
                        request.getContext() + ", skipping SAML 2.0 based single-sign-on/single-logout...");
            }
            getNext().invoke(request, response);
            return;
        }

        //  checks if single-sign-on feature is enabled
        if (!this.contextConfiguration.isSSOEnabled()) {
            containerLog.info("SAML 2.0 single-sign-on not enabled in web app " + request.getContext().getName() +
                    ", skipping SAML 2.0 based single-sign-on...");
            //  moves onto the next valve, if single-sign-on is not enabled
            getNext().invoke(request, response);
            return;
        }

        agentConfiguration = (SSOAgentConfiguration) (request.getSessionInternal().getNote(Constants.SSO_AGENT_CONFIG));
        if (agentConfiguration == null) {
            try {
                agentConfiguration = createAgent(request);
                request.getSessionInternal().setNote(Constants.SSO_AGENT_CONFIG, agentConfiguration);
            } catch (SSOException e) {
                containerLog.warn("Error when initializing the SAML 2.0 single-sign-on agent", e);
                getNext().invoke(request, response);
                return;
            }
        }

        requestResolver = new SSOAgentRequestResolver(request, agentConfiguration);
        //  if the request URL matches one of the URL(s) to skip, moves on to the next valve
        if (requestResolver.isURLToSkip()) {
            containerLog.info("Request matched a URL to skip. Skipping...");
            getNext().invoke(request, response);
            return;
        }

        try {
            if ((requestResolver.isSAMLAuthnRequestURL()) || (request.getSession(false) == null) || (
                    request.getSession(false).getAttribute(Constants.SESSION_BEAN) == null)) {
                containerLog.info("Processing an SAML 2.0 Authentication Request...");
                handleUnauthenticatedRequest(request, response);
                return;
            } else if (requestResolver.isSAML2SSOResponse()) {
                containerLog.info("Processing a SAML 2.0 Response...");
                handleResponse(request, response);
                return;
            } else if (requestResolver.isSAML2SLORequest()) {
                //  Handles single logout request from the identity provider
                containerLog.info("Processing Single Logout Request...");
                SAMLSSOManager manager = new SAMLSSOManager(agentConfiguration);
                manager.performSingleLogout(request);
            } else if (requestResolver.isSLOURL()) {
                //  Handles single logout request initiated directly at the service provider
                containerLog.info("Processing Single Logout URL...");
                handleLogoutRequest(request, response);
                return;
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
     * @param request       the servlet request processed
     */
    private void setDefaultConfigurations(Request request) {
        contextConfiguration.setApplicationServerURL(Optional.ofNullable(contextConfiguration.getApplicationServerURL())
                .orElse(SSOUtils.constructApplicationServerURL(request)
                        .orElse(null)));
        contextConfiguration.setConsumerURLPostfix(Optional.ofNullable(contextConfiguration.getConsumerURLPostfix())
                .orElse(Constants.DEFAULT_CONSUMER_URL_POSTFIX));
        contextConfiguration.enableHandlingConsumerURLAfterSLO(
                Optional.ofNullable(contextConfiguration.handleConsumerURLAfterSLO())
                        .orElse(false));
    }

    /**
     * Creates a single-sign-on (SSO) agent based on the configurations specified.
     *
     * @param request the servlet request processed
     * @return the created single-sign-on (SSO) agent instance
     * @throws SSOException if an error occurs during the validation of the constructed agent
     */
    private SSOAgentConfiguration createAgent(Request request) throws SSOException {
        SSOAgentConfiguration ssoAgentConfiguration = new SSOAgentConfiguration(request);
        setDefaultConfigurations(request);

        ssoAgentConfiguration.initialize(serverConfiguration, contextConfiguration);

        ssoAgentConfiguration.getSAML2().setSSOX509Credential(
                new SSOX509Credential(serverConfiguration.getIdpCertificateAlias(),
                        ServerConfigurationLoader.getServerConfiguration().getSecurityConfiguration()));

        //  retrieves the request context path and the host's web application base
        String contextPath = request.getContextPath();
        String appBase = request.getHost().getAppBase();
        //  generates the service provider entity ID
        String issuerID = SSOUtils.generateIssuerID(contextPath, appBase)
                .orElse("");
        //  generates the SAML 2.0 Assertion Consumer URL
        String consumerURL = SSOUtils.generateConsumerURL(contextPath, contextConfiguration)
                .orElse("");
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
     * @param request  the servlet request processed
     * @param response the servlet response generated
     * @throws SSOException if an error occurs when handling an unauthenticated request
     */
    private void handleUnauthenticatedRequest(Request request, Response response) throws SSOException {
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
                .ifPresent(agent -> agent.getSAML2().enablePassiveAuthentication(false));
        if (requestResolver.isHttpPOSTBinding()) {
            containerLog.info("Handling the SAML 2.0 Authentication Request for HTTP-POST binding...");
            String htmlPayload = manager.handleAuthnRequestForPOSTBinding(request);
            SSOUtils.sendCharacterData(response, htmlPayload);
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

    /**
     * Handles single-sign-on (SSO) and single-logout (SLO) responses.
     *
     * @param request  the servlet request processed
     * @param response the servlet response generated
     * @throws SSOException if an error occurs when handling a response
     */
    private void handleResponse(Request request, Response response) throws SSOException {
        SAMLSSOManager manager = new SAMLSSOManager(agentConfiguration);
        Optional<String> redirectPath = captureRedirectPathAfterSLO(request);
        manager.processResponse(request);
        //  TODO: handle redirect path when absent
        redirectAfterProcessingResponse(request, response, redirectPath.get());
    }

    /**
     * Returns the redirect path after single-logout (SLO), read from the {@code request}.
     * <p>
     * If the redirect path is read from session then it is removed. Priority order of reading the redirect
     * path is from session, context and context-level configuration, respectively.
     *
     * @param request the servlet request processed
     * @return redirect path relative to the current application path
     */
    private Optional<String> captureRedirectPathAfterSLO(Request request) {
        //  reads the redirect path, this has to read before the session get invalidated as it first
        //  tries to read the redirect path from the session attribute
        String redirectPath = null;

        if (request.getSession(false) != null) {
            redirectPath = (String) request.getSession(false).getAttribute(Constants.REDIRECT_PATH_AFTER_SLO);
            request.getSession(false).removeAttribute(Constants.REDIRECT_PATH_AFTER_SLO);
        }
        redirectPath = Optional.ofNullable(redirectPath)
                .orElse(request.getContext().findParameter(Constants.REDIRECT_PATH_AFTER_SLO));

        Optional<WebAppSingleSignOn.Property> property = SSOUtils.
                getContextPropertyValue(contextConfiguration.getProperties(), Constants.REDIRECT_PATH_AFTER_SLO);
        if (property.isPresent()) {
            redirectPath = Optional.ofNullable(redirectPath)
                    .orElse(property.get().getValue());
        }

        if ((redirectPath != null) && (!redirectPath.isEmpty())) {
            redirectPath = request.getContext().getPath().concat(redirectPath);
        } else {
            redirectPath = request.getContext().getPath();
        }

        if (containerLog.isDebugEnabled()) {
            Optional.ofNullable(redirectPath)
                    .ifPresent(path -> containerLog.debug("Redirect path = " + path));
        }

        return Optional.ofNullable(redirectPath);
    }

    /**
     * Handles redirection after processing a SAML 2.0 based Response.
     *
     * @param request      the servlet request processed
     * @param response     the servlet response generated
     * @param redirectPath the redirect path obtained before processing a logout response
     * @throws SSOException if an error occurs when redirecting
     */
    private void redirectAfterProcessingResponse(Request request, Response response, String redirectPath)
            throws SSOException {
        //  redirect according to relay state attribute
        try {
            String relayStateId = agentConfiguration.getSAML2().getRelayState();
            if ((relayStateId != null) && (request.getSession(false) != null)) {
                RelayState relayState = (RelayState) request.getSession(false).getAttribute(relayStateId);
                if (relayState != null) {
                    request.getSession(false).removeAttribute(relayStateId);
                    StringBuilder requestedURI = new StringBuilder(relayState.getRequestedURL());
                    relayState.getRequestQueryString().
                            ifPresent(queryString -> requestedURI.append("?").append(queryString));
                    relayState.getRequestParameters().ifPresent(queryParameters -> request.getSession(false).
                            setAttribute(Constants.REQUEST_PARAM_MAP, queryParameters));
                    response.sendRedirect(requestedURI.toString());
                } else {
                    response.sendRedirect(contextConfiguration.getApplicationServerURL() + request.getContextPath());
                }
            } else if (request.getRequestURI().endsWith(contextConfiguration.getConsumerURLPostfix())
                    && contextConfiguration.handleConsumerURLAfterSLO()) {
                //  handles redirect from acs page after SLO response, this will be done if
                //  SAMLSSOValveConstants.HANDLE_CONSUMER_URL_AFTER_SLO is defined
                //  SAMLSSOValveConstants.REDIRECT_PATH_AFTER_SLO value is used determine the redirect path
                response.sendRedirect(redirectPath);
            }
        } catch (IOException e) {
            throw new SSOException("Error during redirecting after processing SAML 2.0 Response", e);
        }
    }

    /**
     * Handles a logout request from a session participant.
     *
     * @param request  the servlet request processed
     * @param response the servlet response generated
     * @throws SSOException if an error occurs when handling a logout request
     */
    private void handleLogoutRequest(Request request, Response response) throws SSOException {
        SAMLSSOManager manager = new SAMLSSOManager(agentConfiguration);
        try {
            if (requestResolver.isHttpPOSTBinding()) {
                if (request.getSession(false).getAttribute(Constants.SESSION_BEAN) != null) {
                    agentConfiguration.getSAML2().enablePassiveAuthentication(false);
                    String htmlPayload = manager.handleLogoutRequestForPOSTBinding(request);
                    SSOUtils.sendCharacterData(response, htmlPayload);
                } else {
                    containerLog.warn("Attempt to logout from a already logout session");
                    response.sendRedirect(request.getContext().getPath());
                }
            } else {
                agentConfiguration.getSAML2().enablePassiveAuthentication(false);
                response.sendRedirect(manager.handleLogoutRequestForRedirectBinding(request));
            }
        } catch (IOException e) {
            throw new SSOException("Error when handling logout request", e);
        }
    }
}
