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
package org.wso2.appserver.webapp.security.utils;

import org.apache.catalina.connector.Request;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.EncryptedKey;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.wso2.appserver.configuration.context.WebAppSingleSignOn;
import org.wso2.appserver.configuration.server.AppServerSecurity;
import org.wso2.appserver.webapp.security.Constants;
import org.wso2.appserver.webapp.security.bean.RelayState;
import org.wso2.appserver.webapp.security.saml.signature.SSOX509Credential;
import org.wso2.appserver.webapp.security.saml.signature.X509CredentialImplementation;
import org.wso2.appserver.webapp.security.utils.exception.SSOException;
import org.xml.sax.EntityResolver;
import org.xml.sax.SAXException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * This class contains utility functions used within the single-sign-on (SSO) implementation.
 *
 * @since 6.0.0
 */
public class SSOUtils {
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

    //  TODO: check the algorithm and improve
    /**
     * Generates a unique id.
     *
     * @return a unique id
     */
    public static String createID() {
        byte[] bytes = new byte[20]; // 160 bit
        random.nextBytes(bytes);
        char[] characterMapping = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};

        char[] characters = new char[40];
        IntStream.range(0, bytes.length)
                .forEach(index -> {
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
            Stream.of(queryParameterString.split("&"))
                    .map(queryParameter -> queryParameter.split("="))
                    .forEach(splitParameters -> {
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
     * Returns a {@code Property} which matches the {@code key} specified.
     *
     * @param properties the list of properties
     * @param key        the {@link String} representation of the key
     * @return the optional {@link org.wso2.appserver.configuration.context.WebAppSingleSignOn.Property}
     */
    public static Optional<WebAppSingleSignOn.Property> getContextPropertyValue(
            List<WebAppSingleSignOn.Property> properties, String key) {
        if (properties != null) {
            return properties
                    .stream()
                    .filter(property -> property.getValue().equals(key))
                    .findFirst();
        } else {
            return Optional.empty();
        }
    }

    /**
     * Returns a unique id value for the SAML 2.0 service provider application based on its context path.
     * <p>
     * An optional id is returned based on the context path provided.
     *
     * @param contextPath the context path of the service provider application
     * @param hostAppBase the name of the Tomcat host's web application base
     * @return a unique id value for the SAML 2.0 service provider application based on its context path
     */
    public static Optional<String> generateIssuerID(String contextPath, String hostAppBase) {
        if (contextPath != null) {
            String issuerId = contextPath.replaceFirst("/" + hostAppBase, "").replace("/", "_");
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
    public static Optional<String> generateConsumerURL(String contextPath, WebAppSingleSignOn configuration) {
        if ((contextPath != null) && (configuration != null)) {
            return Optional.
                    of(configuration.getApplicationServerURL() + contextPath + configuration.getConsumerURLPostfix());
        } else {
            return Optional.empty();
        }
    }

    /**
     * Returns a {@code KeyStore} based on keystore properties specified.
     *
     * @param configuration the keystore properties
     * @return the {@link KeyStore} instance generated
     * @throws SSOException if an error occurs while generating the {@link KeyStore} instance
     */
    public static Optional generateKeyStore(AppServerSecurity configuration) throws SSOException {
        if ((configuration == null) || (configuration.getKeystore() == null)) {
            return Optional.empty();
        }

        AppServerSecurity.Keystore keystoreConfiguration = configuration.getKeystore();

        String keystorePathString = keystoreConfiguration.getLocation();
        String keystorePasswordString = keystoreConfiguration.getPassword();
        if ((keystorePasswordString == null) || (keystorePathString == null)) {
            return Optional.empty();
        }

        Path keyStorePath = Paths.get(URI.create(keystorePathString).getPath());
        if (Files.exists(keyStorePath)) {
            try (InputStream keystoreInputStream = Files.newInputStream(keyStorePath)) {
                KeyStore keyStore = KeyStore.getInstance(keystoreConfiguration.getType());
                keyStore.load(keystoreInputStream, keystorePasswordString.toCharArray());
                return Optional.of(keyStore);
            } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
                throw new SSOException("Error while loading the key store", e);
            }
        } else {
            throw new SSOException("File path specified for the keystore does not exist");
        }
    }

    /**
     * Utility functions of the flow of single-sign-on and single-logout.
     */

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
        //  TODO: check why request parameters are needed
        relayState.setRequestParameters(request.getParameterMap());

        return relayState;
    }

    /**
     * Sends character data specified by the {@code htmlPayload} in the servlet response body.
     *
     * @param response    the servlet response body in which character data are to be sent
     * @param htmlPayload the character data to be sent in the servlet body
     * @throws SSOException if an error occurs while writing character data to the servlet
     *                      response body
     */
    public static void sendCharacterData(HttpServletResponse response, String htmlPayload) throws SSOException {
        try {
            Writer writer = response.getWriter();
            writer.write(htmlPayload);
            response.flushBuffer();
            //  not closing the Writer instance, as its creator is the HttpServletResponse
        } catch (IOException e) {
            throw new SSOException("Error occurred while writing to HttpServletResponse", e);
        }
    }

    /**
     * OpenSAML utility functions.
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
            throw new SSOException("Error occurred while encoding SAML 2.0 Request, failed to marshall the SAML 2.0. " +
                    "Request element XMLObject to its corresponding W3C DOM element", e);
        }

        StringWriter writer = new StringWriter();
        //  writes the node out to the writer using the DOM
        XMLHelper.writeNode(authDOM, writer);

        if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(binding)) {
            //  compresses the message using default DEFLATE encoding, Base 64 encode and URL encode
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            try (DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream,
                    deflater)) {
                deflaterOutputStream.write(writer.toString().getBytes(Charset.forName(Constants.UTF8_ENC)));
            } catch (IOException e) {
                throw new SSOException("Error occurred while deflate encoding SAML 2.0 request", e);
            }

            String encodedRequestMessage = Base64.
                    encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);
            try {
                return URLEncoder.encode(encodedRequestMessage, Constants.UTF8_ENC).trim();
            } catch (UnsupportedEncodingException e) {
                throw new SSOException("Error occurred while encoding SAML 2.0 request", e);
            }
        } else {
            //  HTTP binding urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST is used, if the binding type encountered
            //  is HTTP-POST binding or if an unsupported binding type is encountered
            return Base64.encodeBytes(writer.toString().getBytes(Charset.forName(Constants.UTF8_ENC)),
                    Base64.DONT_BREAK_LINES);
        }
    }

    /**
     * Serializes the specified SAML 2.0 based XML content representation to its corresponding actual XML syntax
     * representation.
     *
     * @param xmlObject the SAML 2.0 based XML content object
     * @return a {@link String} representation of the actual XML representation of the SAML 2.0 based XML content
     * representation
     * @throws SSOException if an error occurs during the marshalling process
     */
    public static String marshall(XMLObject xmlObject) throws SSOException {
        try {
            MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
            Element element = marshaller.marshall(xmlObject);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
            DOMImplementationLS implementation = (DOMImplementationLS) registry.getDOMImplementation("LS");
            LSSerializer writer = implementation.createLSSerializer();
            LSOutput output = implementation.createLSOutput();
            output.setByteStream(byteArrayOutputStream);
            writer.write(element, output);
            return new String(byteArrayOutputStream.toByteArray(), Charset.forName(Constants.UTF8_ENC));
        } catch (ClassNotFoundException | InstantiationException | MarshallingException | IllegalAccessException e) {
            throw new SSOException("Error in marshalling SAML Assertion", e);
        }
    }

    /**
     * Returns a SAML 2.0 based XML content representation from the string value representing the XML syntax.
     *
     * @param xmlString the {@link String} representation of the XML content
     * @return an XML object from the {@link String} value representing the XML syntax
     * @throws SSOException if an error occurs when unmarshalling the XML string representation
     */
    public static XMLObject unmarshall(String xmlString) throws SSOException {
        try {
            DocumentBuilder docBuilder = SSOUtils.getDocumentBuilder(false, true, new XMLEntityResolver());
            ByteArrayInputStream inputStream = new ByteArrayInputStream(
                    xmlString.getBytes(Charset.forName(Constants.UTF8_ENC)));
            Document document = docBuilder.parse(inputStream);
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            return unmarshaller.unmarshall(element);
        } catch (UnmarshallingException | SAXException | IOException e) {
            throw new SSOException("Error in unmarshalling the XML string representation", e);
        }
    }

    /**
     * Returns a decrypted SAML 2.0 {@code Assertion} from the specified SAML 2.0 encrypted {@code Assertion}.
     *
     * @param ssoAgentX509Credential credential for the resolver
     * @param encryptedAssertion     the {@link EncryptedAssertion} instance to be decrypted
     * @return a decrypted SAML 2.0 {@link Assertion} from the specified SAML 2.0 {@link EncryptedAssertion}
     * @throws SSOException if an error occurs during the decryption process
     */
    public static Assertion decryptAssertion(SSOX509Credential ssoAgentX509Credential,
            EncryptedAssertion encryptedAssertion) throws SSOException {
        try {
            KeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(
                    new X509CredentialImplementation(ssoAgentX509Credential));

            Optional<EncryptedKey> key = encryptedAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys()
                    .stream()
                    .findFirst();
            EncryptedKey encryptedKey = null;
            if (key.isPresent()) {
                encryptedKey = key.get();
            }
            Decrypter decrypter = new Decrypter(null, keyResolver, null);
            SecretKey decrypterKey = (SecretKey) decrypter.decryptKey(encryptedKey, encryptedAssertion.getEncryptedData().
                    getEncryptionMethod().getAlgorithm());
            Credential shared = SecurityHelper.getSimpleCredential(decrypterKey);
            decrypter = new Decrypter(new StaticKeyInfoCredentialResolver(shared), null, null);
            decrypter.setRootInNewDocument(true);
            return decrypter.decrypt(encryptedAssertion);
        } catch (DecryptionException e) {
            throw new SSOException("Decrypted assertion error", e);
        }
    }

    /**
     * Returns the SAML 2.0 Assertion Attribute Statement content.
     *
     * @param assertion the SAML Assertion whose content is to be returned
     * @return the SAML 2.0 Assertion Attribute Statement content of the SAML 2.0 Assertion specified
     */
    public static Map<String, String> getAssertionStatements(Assertion assertion) {
        Map<String, String> results = new HashMap<>();
        if ((assertion != null) && (assertion.getAttributeStatements() != null)) {
            Stream<AttributeStatement> attributeStatements = assertion.getAttributeStatements().stream();
            attributeStatements.
                    forEach(attributeStatement -> attributeStatement.getAttributes()
                            .stream()
                            .forEach(attribute -> {
                                Optional<XMLObject> value = attribute.getAttributeValues()
                                        .stream()
                                        .findFirst();
                                if (value.isPresent()) {
                                    String attributeValue = value.get().getDOM().getTextContent();
                                    results.put(attribute.getName(), attributeValue);
                                }
                            }));
        }
        return results;
    }

    /**
     * XML parse utility function.
     */

    /**
     * Generates a {@code javax.xml.parsers.DocumentBuilder} instance based on the specified configurations.
     *
     * @param expandEntityReferences true if the parser is to expand entity reference nodes, else false
     * @param namespaceAware         true if the parser provides support for XML namespaces, else false
     * @param entityResolver         the {@link EntityResolver} to be used within the parser, if {@code entityResolver}
     *                               is set to null default implementation is used
     * @return the generated {@link DocumentBuilder} instance
     * @throws SSOException if an error occurs when generating the new DocumentBuilder
     */
    private static DocumentBuilder getDocumentBuilder(boolean expandEntityReferences, boolean namespaceAware,
            EntityResolver entityResolver) throws SSOException {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        if (!expandEntityReferences) {
            documentBuilderFactory.setExpandEntityReferences(false);
        }
        if (namespaceAware) {
            documentBuilderFactory.setNamespaceAware(true);
        }

        DocumentBuilder docBuilder;
        try {
            docBuilder = documentBuilderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new SSOException("Error when generating the new DocumentBuilder", e);
        }
        Optional.ofNullable(entityResolver).ifPresent(docBuilder::setEntityResolver);

        return docBuilder;
    }
}
