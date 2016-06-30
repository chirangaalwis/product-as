/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied. See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.wso2.appserver.test.integration;

/**
 * This class defines the constants used during integration tests.
 *
 * @since 6.0.0
 */
public final class TestConstants {
    //  system property constant names
    public static final String APPSERVER_HOME = "appserver.home";
    public static final String SERVER_TIMEOUT = "listener.server.timeout";
    public static final String APPSERVER_PORT = "appserver.port";
    public static final String PORT_CHECK_MIN = "port.check.min";
    public static final String PORT_CHECK_MAX = "port.check.max";
    public static final String TOMCAT_DEFAULT_PORT_NAME = "Tomcat port";
    public static final String TOMCAT_AJP_PORT_NAME = "AJP port";
    public static final String TOMCAT_SERVER_SHUTDOWN_PORT_NAME = "Server shutdown port";

    //  default port number constants
    public static final int TOMCAT_DEFAULT_PORT = 8080;
    public static final int TOMCAT_DEFAULT_AJP_PORT = 8009;
    public static final int TOMCAT_DEFAULT_SERVER_SHUTDOWN_PORT = 8005;

    //  HTTP method constants
    public static final String HTTP_GET_METHOD = "GET";

    //  Apache Tomcat Valves
    public static final String CONFIGURATION_LOADER_SAMPLE_VALVE = "org.wso2.appserver.sample.ConfigurationLoaderValve";
    public static final String HTTP_STATISTICS_PUBLISHING_VALVE = "org.wso2.appserver.monitoring.HttpStatValve";
    public static final String SAML2_SSO_VALVE = "org.wso2.appserver.webapp.security.saml.SAML2SSOValve";
}
