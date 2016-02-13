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
package org.wso2.appserver.utils.model;

import org.wso2.appserver.utils.Constants;

import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * This class defines the configuration properties for Application Server functions.
 *
 * @since 6.0.0
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = Constants.WSO2_CONFIG_XML_ROOT_ELEMENT, namespace = Constants.WSO2_NAMESPACE)
public class Configuration {
    @XmlElement(name = Constants.SSOConfigurationConstants.SINGLE_SIGN_ON, namespace = Constants.WSO2_NAMESPACE)
    private SingleSignOnConfiguration singleSignOnConfiguration;
    @XmlElement(name = Constants.ClassLoadingConfigurationConstants.CLASSLOADING, namespace = Constants.WSO2_NAMESPACE)
    private ClassLoadingConfiguration classLoadingConfiguration;
    @XmlElement(name = "restWebServices", namespace = Constants.WSO2_NAMESPACE)
    private RestWebServicesConfiguration restWebServicesConfiguration;

    public SingleSignOnConfiguration getSingleSignOnConfiguration() {
        return singleSignOnConfiguration;
    }

    public ClassLoadingConfiguration getClassLoadingConfiguration() {
        return classLoadingConfiguration;
    }

    public RestWebServicesConfiguration getRestWebServicesConfiguration() {
        return restWebServicesConfiguration;
    }

    /**
     * A nested class which represents a holder for Application Server class-loading configurations.
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class ClassLoadingConfiguration {
        @XmlElement(name = Constants.ClassLoadingConfigurationConstants.ENVIRONMENTS,
                namespace = Constants.WSO2_NAMESPACE)
        private Environments environments;

        public Environments getEnvironments() {
            return environments;
        }

        /**
         * A nested class which models a group of class-loading environments for Application Server.
         */
        @XmlAccessorType(XmlAccessType.FIELD)
        public static class Environments {
            @XmlElement(name = Constants.ClassLoadingConfigurationConstants.ENVIRONMENT,
                    namespace = Constants.WSO2_NAMESPACE)
            private List<Environment> environments;

            public List<Environment> getEnvironments() {
                return environments;
            }
        }

        /**
         * A nested class which models a class-loading environment for Application Server.
         */
        @XmlAccessorType(XmlAccessType.FIELD)
        public static class Environment {
            @XmlElement(namespace = Constants.WSO2_NAMESPACE)
            private String name;
            @XmlElement(name = Constants.ClassLoadingConfigurationConstants.CLASSPATH,
                    namespace = Constants.WSO2_NAMESPACE)
            private List<String> classpaths;

            public String getName() {
                return name;
            }

            public List<String> getClasspaths() {
                return classpaths;
            }
        }
    }

    /**
     * A nested class which represents a holder for Application Server REST Web Service configurations.
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class RestWebServicesConfiguration {
        @XmlElement(name = Constants.RestWebServicesConfigurationConstants.ISMANAGEDAPI,
                namespace = Constants.WSO2_NAMESPACE)
        private Boolean isManagedAPI;

        public Boolean getIsManagedAPI() {
            return isManagedAPI;
        }
    }
}
