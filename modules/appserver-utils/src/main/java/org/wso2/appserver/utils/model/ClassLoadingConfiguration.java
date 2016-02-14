package org.wso2.appserver.utils.model;

import org.wso2.appserver.utils.Constants;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import java.util.List;

/**
 * A class which represents a holder for Application Server class-loading configurations.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class ClassLoadingConfiguration {
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
