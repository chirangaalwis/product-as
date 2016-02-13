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

/**
 * A Java class which represents a holder for Application Server single-sign-on (SSO) configurations.
 *
 * @since 6.0.0
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class SingleSignOnConfiguration {
    @XmlElement(namespace = Constants.WSO2_NAMESPACE)
    private SkipURIs skipURIs;
    @XmlElement(namespace = Constants.WSO2_NAMESPACE)
    private String applicationServerURL;
    @XmlElement(namespace = Constants.WSO2_NAMESPACE)
    private boolean handleConsumerURLAfterSLO;
    @XmlElement(namespace = Constants.WSO2_NAMESPACE)
    private String loginURL;
    @XmlElement(namespace = Constants.WSO2_NAMESPACE)
    private SAML saml;

    public SkipURIs getSkipURIs() {
        return skipURIs;
    }

    public String getApplicationServerURL() {
        return applicationServerURL;
    }

    public boolean isHandleConsumerURLAfterSLO() {
        return handleConsumerURLAfterSLO;
    }

    public String getLoginURL() {
        return loginURL;
    }

    public SAML getSaml() {
        return saml;
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class SkipURIs {
        @XmlElement(name = Constants.SSOConfigurationConstants.SKIP_URI, namespace = Constants.WSO2_NAMESPACE)
        private List<String> skipURIs;
    }

    /**
     * A nested class which defines the SAML specific single-sign-on (SSO) configurations.
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class SAML {
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private Boolean enableSAMLSSO;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private String idpURL;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private String idpEntityId;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private String issuerId;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private String consumerURL;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private String httpBinding;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private String attributeConsumingServiceIndex;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private Boolean enableSLO;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private String consumerURLPostFix;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private String requestURLPostFix;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private String sloURLPostFix;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private Boolean enableResponseSigning;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private Boolean enableAssertionSigning;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private Boolean enableAssertionEncryption;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private Boolean enableRequestSigning;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private String signatureValidatorImplClass;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private String additionalRequestParams;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private Boolean isForceAuthn;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private Boolean isPassiveAuthn;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private String keystorePath;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private String keystorePassword;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private String idpCertificateAlias;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private String privateKeyAlias;
        @XmlElement(namespace = Constants.WSO2_NAMESPACE)
        private String privateKeyPassword;

        public String getSloURLPostFix() {
            return sloURLPostFix;
        }

        public Boolean getEnableSAMLSSO() {
            return enableSAMLSSO;
        }

        public String getIdpURL() {
            return idpURL;
        }

        public String getIdpEntityId() {
            return idpEntityId;
        }

        public String getIssuerId() {
            return issuerId;
        }

        public String getConsumerURL() {
            return consumerURL;
        }

        public String getHttpBinding() {
            return httpBinding;
        }

        public String getAttributeConsumingServiceIndex() {
            return attributeConsumingServiceIndex;
        }

        public Boolean getEnableSLO() {
            return enableSLO;
        }

        public String getConsumerURLPostFix() {
            return consumerURLPostFix;
        }

        public String getRequestURLPostFix() {
            return requestURLPostFix;
        }

        public Boolean getEnableResponseSigning() {
            return enableResponseSigning;
        }

        public Boolean getEnableAssertionSigning() {
            return enableAssertionSigning;
        }

        public Boolean getEnableAssertionEncryption() {
            return enableAssertionEncryption;
        }

        public Boolean getEnableRequestSigning() {
            return enableRequestSigning;
        }

        public String getSignatureValidatorImplClass() {
            return signatureValidatorImplClass;
        }

        public String getAdditionalRequestParams() {
            return additionalRequestParams;
        }

        public Boolean getIsForceAuthn() {
            return isForceAuthn;
        }

        public Boolean getIsPassiveAuthn() {
            return isPassiveAuthn;
        }

        public String getKeystorePath() {
            return keystorePath;
        }

        public String getKeystorePassword() {
            return keystorePassword;
        }

        public String getIdpCertificateAlias() {
            return idpCertificateAlias;
        }

        public String getPrivateKeyAlias() {
            return privateKeyAlias;
        }

        public String getPrivateKeyPassword() {
            return privateKeyPassword;
        }
    }
}
