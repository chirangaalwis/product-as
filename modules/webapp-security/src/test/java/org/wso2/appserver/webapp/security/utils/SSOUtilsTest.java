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

import org.apache.catalina.Host;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.Request;
import org.apache.catalina.core.StandardHost;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.appserver.configuration.context.WebAppSingleSignOn;
import org.wso2.appserver.configuration.server.AppServerSecurity;
import org.wso2.appserver.webapp.security.Constants;
import org.wso2.appserver.webapp.security.TestConstants;
import org.wso2.appserver.webapp.security.TestUtils;
import org.wso2.appserver.webapp.security.bean.RelayState;
import org.wso2.appserver.webapp.security.utils.exception.SSOException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.IntStream;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * This class defines unit test cases for single-sign-on (SSO) utility functions.
 *
 * @since 6.0.0
 */
public class SSOUtilsTest {
    @Test(description = "Tests the construction of Application Server URL for a sample request")
    public void testConstructionOfApplicationServerURL() {
        Request request = new Request();

        Connector connector = new Connector();
        connector.setProtocol(TestConstants.SSL_PROTOCOL);
        connector.setPort(TestConstants.SSL_PORT);
        request.setConnector(connector);

        Host host = new StandardHost();
        host.setName(TestConstants.DEFAULT_TOMCAT_HOST);
        request.getMappingData().host = host;

        Optional<String> actual = SSOUtils.constructApplicationServerURL(request);
        if (actual.isPresent()) {
            Assert.assertEquals(actual.get(), TestConstants.DEFAULT_APPLICATION_SERVER_URL);
        } else {
            Assert.fail();
        }
    }

    @Test(description = "Tests the construction of Application Server URL for an invalid 'null' request")
    public void testConstructionOfApplicationServerURLFromInvalidRequest() {
        Optional<String> actual = SSOUtils.constructApplicationServerURL(null);
        Assert.assertTrue(!actual.isPresent());
    }

    @Test(description = "Tests the validity of the split query parameter string")
    public void testQueryParamStringSplit() {
        Map<String, String[]> expected = getExpectedQueryParams();

        String testQueryString = "key1=key1val1&key1=key1val2&key2=key2val1&key2=key2val2&key3=key3val1";
        Map<String, String[]> actual = SSOUtils.getSplitQueryParameters(testQueryString);

        Assert.assertTrue(equalMaps(expected, actual));
    }

    @Test(description = "Tests the uniqueness of the id generated")
    public void testUniqueIDCreation() {
        List<String> ids = new ArrayList<>();
        IntStream
                .range(0, 10)
                .forEach(index -> ids.add(SSOUtils.createID()));

        Set<String> uniqueIds = new HashSet<>();
        ids
                .stream()
                .forEach(uniqueIds::add);

        Assert.assertTrue(ids.size() == uniqueIds.size());
    }

    @Test(description = "Tests the validity of the issuer ID generated from a valid context path")
    public void testGeneratingIssuerID() {
        String contextPath = "/" + TestConstants.WEB_APP_BASE + TestConstants.CONTEXT_PATH;

        Optional<String> actualIssuerID = SSOUtils.generateIssuerID(contextPath, TestConstants.WEB_APP_BASE);
        Assert.assertTrue(
                (actualIssuerID.isPresent()) && (actualIssuerID.get().equals(TestConstants.CONTEXT_PATH.substring(1))));
    }

    @Test(description = "Tests the validity of the issuer ID generated from an invalid context path")
    public void testGeneratingIssuerIDFromInvalidContextPath() {
        Optional<String> actualIssuerID = SSOUtils.generateIssuerID(null, TestConstants.WEB_APP_BASE);
        Assert.assertTrue(!actualIssuerID.isPresent());
    }

    @Test(description = "Tests the validity of the consumer URL generated from a valid context path")
    public void testGeneratingConsumerURL() {
        WebAppSingleSignOn ssoConfiguration = new WebAppSingleSignOn();
        ssoConfiguration.setApplicationServerURL(TestConstants.DEFAULT_APPLICATION_SERVER_URL);
        ssoConfiguration.setConsumerURLPostfix(Constants.DEFAULT_CONSUMER_URL_POSTFIX);

        String expected = TestConstants.DEFAULT_APPLICATION_SERVER_URL + TestConstants.CONTEXT_PATH +
                Constants.DEFAULT_CONSUMER_URL_POSTFIX;
        Optional<String> actual = SSOUtils.generateConsumerURL(TestConstants.CONTEXT_PATH, ssoConfiguration);

        Assert.assertTrue((actual.isPresent()) && (actual.get().equals(expected)));
    }

    @Test(description = "Tests the validity of the consumer URL generated from an invalid context path")
    public void testGeneratingConsumerURLFromInvalidContextPath() {
        WebAppSingleSignOn ssoConfiguration = new WebAppSingleSignOn();
        ssoConfiguration.setApplicationServerURL(TestConstants.DEFAULT_APPLICATION_SERVER_URL);
        ssoConfiguration.setConsumerURLPostfix(Constants.DEFAULT_CONSUMER_URL_POSTFIX);

        Optional<String> actual = SSOUtils.generateConsumerURL(null, ssoConfiguration);

        Assert.assertTrue(!actual.isPresent());
    }

    @Test(description = "Tests the validity of the relay state instance generated from the sample request")
    public void testGeneratingRelayState() {
        Request request = mock(Request.class);

        when(request.getRequestURI()).thenReturn(TestConstants.NON_AUTHN_REQ_URI);
        when(request.getQueryString()).thenReturn(TestConstants.DEFAULT_QUERY_PARAMS);
        when(request.getParameterMap()).thenReturn(getExpectedQueryParams());

        RelayState actual = SSOUtils.generateRelayState(request);

        boolean equalURI = actual.getRequestedURL().equals(TestConstants.NON_AUTHN_REQ_URI);
        boolean equalQueryString = actual.getRequestQueryString().orElse("").equals(TestConstants.DEFAULT_QUERY_PARAMS);
        @SuppressWarnings("unchecked")
        boolean equalParams = equalMaps(getExpectedQueryParams(),
                actual.getRequestParameters().orElse(new HashMap<>()));

        Assert.assertTrue(equalURI && equalQueryString && equalParams);
    }

    @Test(description = "Tests the generation of keystore from invalid file path",
            expectedExceptions = {SSOException.class})
    public void testGeneratingKeyStoreFromInvalidPath() throws SSOException {
        AppServerSecurity configuration = TestUtils.getDefaultServerSecurityConfiguration();
        AppServerSecurity.Keystore keystore = configuration.getKeystore();
        keystore.setLocation(TestConstants.TEST_RESOURCES_LOCATION + "/conf/wso2carbon.jks");

        SSOUtils.generateKeyStore(configuration);
    }

    @Test(description = "Tests the generation of keystore from invalid password")
    public void testGeneratingKeyStoreFromInvalidPassword() throws SSOException {
        AppServerSecurity configuration = TestUtils.getDefaultServerSecurityConfiguration();
        AppServerSecurity.Keystore keystoreConfiguration = configuration.getKeystore();
        keystoreConfiguration.setPassword(null);

        Optional keystore = SSOUtils.generateKeyStore(configuration);
        Assert.assertTrue(!keystore.isPresent());
    }

    @Test(description = "Tests the geenration of keystore from invalid set of configurations")
    public void testGeneratingKeyStoreFromInvalidConfigurations() throws SSOException {
        Optional keystore = SSOUtils.generateKeyStore(null);
        Assert.assertTrue(!keystore.isPresent());
    }

    @Test(description = "Tests the generation of keystore by providing a non-matching keystore type name",
            expectedExceptions = {SSOException.class})
    public void testGeneratingKeyStoreFromInvalidStoreType() throws SSOException {
        AppServerSecurity configuration = TestUtils.getDefaultServerSecurityConfiguration();
        AppServerSecurity.Keystore keystore = configuration.getKeystore();
        keystore.setType("PKCS");

        SSOUtils.generateKeyStore(configuration);
    }

    private static Map<String, String[]> getExpectedQueryParams() {
        Map<String, String[]> queryParams = new HashMap<>();

        queryParams.put("key1", new String[] { "key1val1", "key1val2" });
        queryParams.put("key2", new String[] { "key2val1", "key2val2" });
        queryParams.put("key3", new String[] { "key3val1" });

        return queryParams;
    }

    private static boolean equalMaps(Map<String, String[]> expected, Map<String, String[]> actual) {
        for (Map.Entry<String, String[]> expectedEntry : expected.entrySet()) {
            String[] expectedArray = expectedEntry.getValue();
            String[] actualArray = actual.get(expectedEntry.getKey());
            if (actualArray == null) {
                return false;
            } else {
                boolean result = equalStringArrays(expectedArray, actualArray);
                if (!result) {
                    return false;
                }
            }
        }

        return true;
    }

    private static boolean equalStringArrays(String[] expected, String[] actual) {
        return Arrays.asList(expected)
                .stream()
                .filter(expectedValue -> Arrays.asList(actual)
                        .stream()
                        .filter(expectedValue::equals)
                        .count() > 0)
                .count() == expected.length;
    }
}
