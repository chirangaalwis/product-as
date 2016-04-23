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
package org.wso2.appserver.configuration.server;

import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlValue;

/**
 * A Java class which models a holder for server level single-sign-on (SSO) configurations.
 *
 * @since 6.0.0
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement
public class ServerSSOConfiguration {
    @XmlElement(name = "IdPURL")
    private String idpURL;
    @XmlElement(name = "IdPEntityId")
    private String idpEntityId;
    @XmlElement(name = "SignatureValidatorImplClass")
    private String signatureValidatorImplClass;
    @XmlElement(name = "IdPCertificateAlias")
    private String idpCertificateAlias;
    @XmlElement(name = "Property")
    private List<Property> properties;

    public String getIdpURL() {
        return idpURL;
    }

    public void setIdpURL(String idpURL) {
        this.idpURL = idpURL;
    }

    public String getIdpEntityId() {
        return idpEntityId;
    }

    public void setIdpEntityId(String idpEntityId) {
        this.idpEntityId = idpEntityId;
    }

    public String getSignatureValidatorImplClass() {
        return signatureValidatorImplClass;
    }

    public void setSignatureValidatorImplClass(String signatureValidatorImplClass) {
        this.signatureValidatorImplClass = signatureValidatorImplClass;
    }

    public String getIdpCertificateAlias() {
        return idpCertificateAlias;
    }

    public void setIdpCertificateAlias(String idpCertificateAlias) {
        this.idpCertificateAlias = idpCertificateAlias;
    }

    public List<Property> getProperties() {
        return properties;
    }

    public void setProperties(List<Property> properties) {
        this.properties = properties;
    }

    /**
     * A nested class which defines an additional configuration property for SSO.
     * <p>
     * The ability to add these key-value pair configuration properties have been added to
     * enable the introduction of new configuration properties with less hassle, in the future.
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class Property {
        @XmlAttribute(name = "Key")
        private String key;
        @XmlValue
        private String value;

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }
}
