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
package org.wso2.appserver.utils.listeners;

import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;
import org.apache.catalina.Server;
import org.wso2.appserver.utils.AppServerException;
import org.wso2.appserver.utils.PathUtils;
import org.wso2.appserver.utils.model.Configuration;

import java.nio.file.Path;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

/**
 * A Java class which acts as an Apache Tomcat Lifecycle Listener, loading the content of the global WSO2 specific
 * configurations file.
 *
 * @since 6.0.0
 */
public class GlobalConfigurationListener implements LifecycleListener {
    private static final Logger logger = Logger.getLogger(GlobalConfigurationListener.class.getName());
    private static Configuration globalConfiguration;

    @Override
    public void lifecycleEvent(LifecycleEvent lifecycleEvent) {
        if (Lifecycle.BEFORE_START_EVENT.equals(lifecycleEvent.getType())) {
            Object source = lifecycleEvent.getSource();
            if (source instanceof Server) {
                try {
                    setGlobalConfiguration();
                } catch (AppServerException e) {
                    logger.log(Level.SEVERE, "An error has occurred when loading the WSO2 global configuration data",
                            e);
                }
            }
        }
    }

    public static Optional<Configuration> getGlobalConfiguration() {
        if (globalConfiguration == null) {
            return Optional.empty();
        } else {
            return Optional.of(globalConfiguration);
        }
    }

    private static synchronized void setGlobalConfiguration() throws AppServerException {
        if (globalConfiguration == null) {
            Optional<Path> schemaPath = Optional.of(PathUtils.getWSO2GlobalConfigurationSchemaFile());
            Unmarshaller unmarshaller = Utils.getXMLUnmarshaller(schemaPath, Configuration.class);
            try {
                globalConfiguration = (Configuration) unmarshaller.
                        unmarshal(PathUtils.getWSO2GlobalConfigurationFile().toFile());
            } catch (JAXBException e) {
                throw new AppServerException("An error has occurred during unmarshalling XML data", e);
            }
        }
    }
}
