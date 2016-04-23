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

import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This class manages the generation of varied request and response types that are utilized
 * within the SAML 2.0 single-sign-on (SSO) and single-logout (SLO) process.
 *
 * @since 6.0.0
 */
public class SAMLSSOManager {
    private SSOAgentConfiguration ssoAgentConfiguration;

    public SAMLSSOManager(SSOAgentConfiguration ssoAgentConfiguration) throws SSOException {
        this.ssoAgentConfiguration = ssoAgentConfiguration;
        //TODO: load signature validator class
        SSOUtils.doBootstrap();
    }

    /**
     * Handles a SAML 2.0 Authentication Request (AuthnRequest) for SAML 2.0 HTTP POST binding.
     *
     * @param request the HTTP servlet request with SAML message
     * @return the HTML payload to be transmitted
     * @throws SSOException if an error occurs when handling AuthnRequest
     */
    protected String handleAuthnRequestForPOSTBinding(HttpServletRequest request) throws SSOException {
        RequestAbstractType requestMessage = buildAuthnRequest(request);
        //TODO: digital signature
        /*if (ssoAgentConfiguration.getSAML2().isRequestSigned()) {
            requestMessage = SSOUtils.
                    setSignature((AuthnRequest) requestMessage, XMLSignature.ALGO_ID_SIGNATURE_RSA,
                            new X509CredentialImplementation(
                                    ssoAgentConfiguration.getSAML2().getSSOAgentX509Credential()));
        }*/

        return preparePOSTRequest(requestMessage);
    }

    /**
     * Handles a SAML 2.0 Authentication Request (AuthnRequest) for SAML 2.0 HTTP Redirect binding.
     *
     * @param request the HTTP servlet request with SAML 2.0 message
     * @return the Identity Provider URL with the query string appended based on the SAML 2.0 Request and configurations
     * @throws SSOException if an error occurs when handling AuthnRequest
     */
    protected String handleAuthnRequestForRedirectBinding(HttpServletRequest request) throws SSOException {
        RequestAbstractType requestMessage = buildAuthnRequest(request);
        return prepareRedirectRequest(requestMessage);
    }

    /**
     * Handles the specified {@code RequestAbstractType} for SAML 2.0 HTTP POST binding.
     *
     * @param rawRequestMessage the {@link RequestAbstractType} which is either a SAML 2.0 AuthnRequest or
     *                          a SAML 2.0 LogoutRequest
     * @return the HTML payload string
     * @throws SSOException if an error occurs when encoding the request message
     */
    private String preparePOSTRequest(RequestAbstractType rawRequestMessage) throws SSOException {
        String encodedRequestMessage = SSOUtils.
                encodeRequestMessage(rawRequestMessage, SAMLConstants.SAML2_POST_BINDING_URI);

        Map<String, String[]> parameters = new HashMap<>();
        parameters.
                put(Constants.HTTP_POST_PARAM_SAML_REQUEST, new String[] { encodedRequestMessage });
        if (ssoAgentConfiguration.getSAML2().getRelayState() != null) {
            parameters.put(Constants.RELAY_STATE_PARAMETER,
                    new String[] { ssoAgentConfiguration.getSAML2().getRelayState() });
        }

        //  Add any additional parameters defined
        if ((ssoAgentConfiguration.getQueryParameters() != null) && (!ssoAgentConfiguration.
                getQueryParameters().isEmpty())) {
            parameters.putAll(ssoAgentConfiguration.getQueryParameters());
        }

        StringBuilder htmlParameters = new StringBuilder();
        parameters.entrySet().stream().
                filter(entry -> ((entry.getKey() != null) &&
                        (entry.getValue() != null) && (entry.getValue().length > 0))).
                forEach(filteredEntry -> Stream.of(filteredEntry.getValue()).
                        forEach(parameter -> htmlParameters.append("<input type='hidden' name='").
                                append(filteredEntry.getKey()).append("' value='").append(parameter).append("'>\n")));

        return "<html>\n" +
                "<body>\n" +
                "<p>You are now redirected back to " + ssoAgentConfiguration.getSAML2().getIdPURL() + " \n" +
                "If the redirection fails, please click the post button.</p>\n" +
                "<form method='post' action='" + ssoAgentConfiguration.getSAML2().getIdPURL() + "'>\n" +
                "<p>\n" +
                htmlParameters.toString() +
                "<button type='submit'>POST</button>\n" +
                "</p>\n" +
                "</form>\n" +
                "<script type='text/javascript'>\n" +
                "document.forms[0].submit();\n" +
                "</script>\n" +
                "</body>\n" +
                "</html>";
    }

    /**
     * Handles the specified {@code RequestAbstractType} for SAML 2.0 Redirect POST binding.
     *
     * @param rawRequestMessage the {@link RequestAbstractType} which is either a SAML 2.0 AuthnRequest or
     *                          a SAML 2.0 LogoutRequest
     * @return the Identity Provider URL with the query string appended based on the SAML 2.0 Request and configurations
     * @throws SSOException if an error occurs when preparing the HTTP Redirect request
     */
    private String prepareRedirectRequest(RequestAbstractType rawRequestMessage) throws SSOException {
        //  Compress the message using default DEFLATE encoding since SAMLEncoding query string parameter
        //  is not specified, perform Base64 encoding and then URL encoding
        String encodedRequestMessage = SSOUtils.
                encodeRequestMessage(rawRequestMessage, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        StringBuilder httpQueryString = new StringBuilder(Constants.HTTP_POST_PARAM_SAML_REQUEST +
                "=" + encodedRequestMessage);

        //  Arrange the query string if any RelayState data is to accompany the SAML protocol message
        String relayState = ssoAgentConfiguration.getSAML2().getRelayState();
        if (relayState != null) {
            try {
                httpQueryString.append("&").append(Constants.RELAY_STATE_PARAMETER).append("=").
                        append(URLEncoder.encode(relayState, "UTF-8").trim());
            } catch (UnsupportedEncodingException e) {
                throw new SSOException("Error occurred while URLEncoding " + Constants.RELAY_STATE_PARAMETER, e);
            }
        }

        //  Add any additional parameters defined
        if ((ssoAgentConfiguration.getQueryParameters() != null) && (!ssoAgentConfiguration.
                getQueryParameters().isEmpty())) {
            StringBuilder builder = new StringBuilder();
            ssoAgentConfiguration.getQueryParameters().entrySet().stream().
                    filter(entry -> ((entry.getKey() != null) &&
                            (entry.getValue() != null) && (entry.getValue().length > 0))).
                    forEach(filteredEntry -> Stream.of(filteredEntry.getValue()).
                            forEach(parameter -> builder.append("&").append(filteredEntry.getKey()).
                                    append("=").append(parameter)));
            httpQueryString.append(builder);
        }

        //TODO: digital signature
        /*if (ssoAgentConfiguration.getSAML2().isRequestSigned()) {
            SSOUtils.addDeflateSignatureToHTTPQueryString(httpQueryString,
                    new X509CredentialImplementation(ssoAgentConfiguration.getSAML2().getSSOAgentX509Credential()));
        }*/

        String idpUrl;
        if (ssoAgentConfiguration.getSAML2().getIdPURL().contains("?")) {
            idpUrl = ssoAgentConfiguration.getSAML2().getIdPURL().concat("&").concat(httpQueryString.toString());
        } else {
            idpUrl = ssoAgentConfiguration.getSAML2().getIdPURL().concat("?").concat(httpQueryString.toString());
        }
        return idpUrl;
    }

    /**
     * Returns a SAML 2.0 Authentication Request (AuthnRequest) instance based on the HTTP servlet request.
     *
     * @param request the HTTP servlet request used to build up the Authentication Request
     * @return a SAML 2.0 Authentication Request (AuthnRequest) instance
     */
    private AuthnRequest buildAuthnRequest(HttpServletRequest request) {
        //  Issuer identifies the entity that generated the request message
        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue(ssoAgentConfiguration.getSAML2().getSPEntityId());

        //  NameIDPolicy element tailors the subject name identifier of assertions resulting from AuthnRequest
        NameIDPolicy nameIdPolicy = new NameIDPolicyBuilder().buildObject();
        //  URI reference corresponding to a name identifier format
        nameIdPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        //  Unique identifier of the service provider or affiliation of providers for whom the identifier was generated
        nameIdPolicy.setSPNameQualifier("Issuer");
        //  Identity provider is allowed, in the course of fulfilling the request to generate a new identifier to
        //  represent the principal
        nameIdPolicy.setAllowCreate(true);

        //  This represents a URI reference identifying an authentication context class that describes the
        //  authentication context declaration that follows
        AuthnContextClassRef authnContextClassRef = new AuthnContextClassRefBuilder().buildObject();
        authnContextClassRef.
                setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

        //  Specifies the authentication context requirements of authentication statements returned in response
        //  to a request or query
        RequestedAuthnContext requestedAuthnContext = new RequestedAuthnContextBuilder().buildObject();
        //  Resulting authentication context in the authentication statement must be the exact match of the
        //  authentication context specified
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
        requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

        DateTime issueInstant = new DateTime();

        //  Create an AuthnRequest instance
        AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();

        authnRequest.setForceAuthn(ssoAgentConfiguration.getSAML2().isForceAuthenticationEnabled());
        authnRequest.setIsPassive(ssoAgentConfiguration.getSAML2().isPassiveAuthenticationEnabled());
        authnRequest.setIssueInstant(issueInstant);
        authnRequest.setProtocolBinding(ssoAgentConfiguration.getSAML2().getHttpBinding());
        authnRequest.setAssertionConsumerServiceURL(ssoAgentConfiguration.getSAML2().getACSURL());
        authnRequest.setIssuer(issuer);
        authnRequest.setNameIDPolicy(nameIdPolicy);
        authnRequest.setRequestedAuthnContext(requestedAuthnContext);
        authnRequest.setID(SSOUtils.createID());
        authnRequest.setVersion(SAMLVersion.VERSION_20);
        authnRequest.setDestination(ssoAgentConfiguration.getSAML2().getIdPURL());

        //  If any optional protocol message extension elements that are agreed on between the communicating parties
        if (request.getAttribute(Extensions.LOCAL_NAME) != null) {
            authnRequest.setExtensions((Extensions) request.getAttribute(Extensions.LOCAL_NAME));
        }

        //  Requesting SAML Attributes which the requester desires to be supplied by the identity provider,
        //  this Index value is registered in the identity provider
        String index = ssoAgentConfiguration.getSAML2().getAttributeConsumingServiceIndex();
        if ((index != null) && !(index.trim().isEmpty())) {
            authnRequest.setAttributeConsumingServiceIndex(Integer.parseInt(index));
        }

        return authnRequest;
    }

    /**
     * Sends character data specified by the {@code htmlPayload} in the servlet response body.
     *
     * @param response    the servlet response body in which character data are to be sent
     * @param htmlPayload the character data to be sent in the servlet body
     * @throws SSOException if an error occurs while writing character data to the servlet
     *                      response body
     */
    protected void sendCharacterData(HttpServletResponse response, String htmlPayload) throws SSOException {
        try {
            Writer writer = response.getWriter();
            writer.write(htmlPayload);
            response.flushBuffer();
            //  Not closing the Writer instance, as its creator is the HttpServletResponse
        } catch (IOException e) {
            throw new SSOException("Error occurred while writing to HttpServletResponse", e);
        }
    }
}
