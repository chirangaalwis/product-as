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
package org.wso2.appserver.utils;

/**
 * This class defines WSO2 Application Server specific utility constants.
 *
 * @since 6.0.0
 */
public class Constants {
    //  Environmental variable property name constant
    public static final String CATALINA_BASE = "catalina.base";
    //  File path related constants
    protected static final String TOMCAT_CONFIGURATION_FOLDER_NAME = "conf";
    protected static final String WSO2_CONFIGURATION_FOLDER_NAME = "wso2";
    protected static final String WSO2AS_CONFIG_FILE_NAME = "wso2as-web.xml";

    public static class SingleSignOnConfigurationConstants {
        public static final String REQUEST_URL_POSTFIX = "requestURLPostFix";
        public static final String ISSUER_ID = "issuerId";
        public static final String ACS_URL = "consumerURL";
        public static final String IDP_ENTITY_ID = "idpEntityId";
        public static final String IDP_URL = "idpURL";
        public static final String ATTRIBUTE_CONSUMING_SERVICE_INDEX = "attributeConsumingServiceIndex";
        public static final String SLO_URL_POSTFIX = "sloURLPostFix";
    }
}
