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

import org.apache.catalina.connector.Request;
import org.apache.commons.lang3.StringUtils;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
import org.wso2.appserver.configuration.context.ContextSSOConfiguration;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

/**
 * This class contains utility functions used within the single-sign-on (SSO) implementation.
 *
 * @since 6.0.0
 */
public class SSOUtils {
    private static final Log log = LogFactory.getLog(SSOUtils.class);
    private static final SecureRandom random = new SecureRandom();
    private static boolean isBootStrapped;

    /**
     * Prevents instantiating the SSOUtils utility class.
     */
    private SSOUtils() {
    }

    /**
     * General utility functions used within the single-sign-on (SSO) implementation.
     */

    /**
     * Generates a unique id.
     *
     * @return a unique id
     */
    public static String createID() {
        byte[] bytes = new byte[20]; // 160 bit
        random.nextBytes(bytes);
        char[] characterMapping = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p' };

        char[] characters = new char[40];
        IntStream.range(0, bytes.length).forEach(index -> {
            int left = (bytes[index] >> 4) & 0x0f;
            int right = bytes[index] & 0x0f;
            characters[index * 2] = characterMapping[left];
            characters[index * 2 + 1] = characterMapping[right];
        });

        return String.valueOf(characters);
    }

    /**
     * Utility functions when initializing SSO agent configurations.
     */

    /**
     * Returns the query parameters split out of the query parameter string.
     *
     * @param queryParameterString the query parameter {@link String}
     * @return the split query parameters
     */
    public static Map<String, String[]> getSplitQueryParameters(String queryParameterString) {
        Map<String, String[]> queryParameters = new HashMap<>();

        if (!StringUtils.isBlank(queryParameterString)) {
            Map<String, List<String>> queryParameterMap = new HashMap<>();
            Stream.of(queryParameterString.split("&")).
                    map(queryParameter -> queryParameter.split("=")).forEach(splitParameters -> {
                if (splitParameters.length == 2) {
                    if (queryParameterMap.get(splitParameters[0]) != null) {
                        queryParameterMap.get(splitParameters[0]).add(splitParameters[1]);
                    } else {
                        List<String> newList = new ArrayList<>();
                        newList.add(splitParameters[1]);
                        queryParameterMap.put(splitParameters[0], newList);
                    }
                }
                queryParameterMap.entrySet().stream().forEach(entry -> {
                    String[] values = entry.getValue().toArray(new String[entry.getValue().size()]);
                    queryParameters.put(entry.getKey(), values);
                });
            });
        }

        return queryParameters;
    }

    /**
     * Returns a unique id value for the SAML 2.0 service provider application based on its context path.
     * <p>
     * An {@code Optional String} id is returned based on the context path provided.
     *
     * @param contextPath the context path of the service provider application
     * @return a unique id value for the SAML 2.0 service provider application based on its context path
     */
    public static Optional<String> generateIssuerID(String contextPath) {
        if (contextPath != null) {
            String issuerId = contextPath.replaceFirst("/webapps", "").replace("/", "_");
            if (issuerId.startsWith("_")) {
                issuerId = issuerId.substring(1);
            }
            return Optional.of(issuerId);
        } else {
            return Optional.empty();
        }
    }

    /**
     * Returns a SAML 2.0 Assertion Consumer URL based on service provider application context path.
     * <p>
     * An {@code Optional String} URL is returned based on the context path and configuration properties provided.
     *
     * @param contextPath   the context path of the service provider application
     * @param configuration the context level single-sign-on configuration properties
     * @return a SAML 2.0 Assertion Consumer URL based on service provider application context path
     */
    public static Optional<String> generateConsumerURL(String contextPath, ContextSSOConfiguration configuration) {
        if ((contextPath != null) && (configuration != null)) {
            return Optional.
                    of(configuration.getApplicationServerURL() + contextPath + configuration.getConsumerURLPostfix());
        } else {
            return Optional.empty();
        }
    }

    /**
     * Generates a {@code RelayState} based on the {@code Request}.
     *
     * @param request the {@link Request} instance
     * @return the created {@link RelayState} instance
     */
    public static RelayState generateRelayState(Request request) {
        RelayState relayState = new RelayState();
        relayState.setRequestedURL(request.getRequestURI());
        relayState.setRequestQueryString(request.getQueryString());
        relayState.setRequestParameters(request.getParameterMap());

        return relayState;
    }

    /**
     * OpenSAML utility functions
     */

    /**
     * Initializes the OpenSAML2 library, if it is not initialized yet.
     * <p>
     * Calls the bootstrap method of {@code DefaultBootstrap}.
     *
     * @throws SSOException if an error occurs when bootstrapping the OpenSAML2 library
     */
    public static void doBootstrap() throws SSOException {
        if (!isBootStrapped) {
            try {
                DefaultBootstrap.bootstrap();
                isBootStrapped = true;
            } catch (ConfigurationException e) {
                throw new SSOException("Error in bootstrapping the OpenSAML2 library", e);
            }
        }
    }

    /**
     * Encodes the SAML 2.0 based request XML object into its corresponding Base64 notation, based on the type of
     * SAML 2.0 binding.
     *
     * @param requestMessage the {@link RequestAbstractType} XML object to be encoded
     * @param binding        the SAML 2.0 binding type
     * @return encoded {@link String} corresponding to the request XML object
     * @throws SSOException if an error occurs while encoding SAML request
     */
    public static String encodeRequestMessage(RequestAbstractType requestMessage, String binding) throws SSOException {
        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(requestMessage);
        Element authDOM;
        try {
            //  marshall this element, and its children, and root them in a newly created Document
            authDOM = marshaller.marshall(requestMessage);
        } catch (MarshallingException e) {
            throw new SSOException("Error occurred while encoding SAML request, failed to marshall the SAML 2.0. "
                    + "Request element XMLObject to its corresponding W3C DOM element", e);
        }

        StringWriter writer = new StringWriter();
        //  writes the node out to the writer using the DOM
        XMLHelper.writeNode(authDOM, writer);

        if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(binding)) {
            //  compress the message using default DEFLATE encoding, Base 64 encode and URL encode
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            try (DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream,
                    deflater)) {
                deflaterOutputStream.write(writer.toString().getBytes(Charset.forName("UTF-8")));
            } catch (IOException e) {
                throw new SSOException("Error occurred while deflate encoding SAML request", e);
            }

            String encodedRequestMessage = Base64.
                    encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);
            try {
                return URLEncoder.encode(encodedRequestMessage, "UTF-8").trim();
            } catch (UnsupportedEncodingException e) {
                throw new SSOException("Error occurred while encoding SAML request", e);
            }
        } else if (SAMLConstants.SAML2_POST_BINDING_URI.equals(binding)) {
            return Base64.
                    encodeBytes(writer.toString().getBytes(Charset.forName("UTF-8")), Base64.DONT_BREAK_LINES);
        } else {
            log.info("Unsupported SAML2 HTTP Binding. Defaulting to " + SAMLConstants.SAML2_POST_BINDING_URI);
            return Base64.
                    encodeBytes(writer.toString().getBytes(Charset.forName("UTF-8")), Base64.DONT_BREAK_LINES);
        }
    }
}
