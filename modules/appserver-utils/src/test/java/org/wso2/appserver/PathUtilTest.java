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
package org.wso2.appserver;

import org.apache.catalina.Globals;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.appserver.utils.PathUtils;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * This class defines the unit-tests for Path related utilities.
 *
 * @since 6.0.0
 */
public class PathUtilTest {
    private static final Path CATALINA_BASE = Paths.get(TestConstants.TEST_RESOURCES, TestConstants.CATALINA_BASE);

    @BeforeClass
    public void setupCatalinaBaseEnv() {
        System.setProperty(Globals.CATALINA_BASE_PROP, CATALINA_BASE.toString());
    }

    @Test(description = "Loads a file path representation of the CATALINA_BASE")
    public void testCatalinaBase() {
        Path actual = PathUtils.getCatalinaBase();
        Assert.assertEquals(actual.toString(), CATALINA_BASE.toString());
    }

    @Test(description = "Loads a file path representation of the Tomcat config-base")
    public void testCatalinaConfigurationHome() {
        Path expected = Paths.get(CATALINA_BASE.toString(), Constants.TOMCAT_CONFIGURATION_DIRECTORY);
        Path actual = PathUtils.getCatalinaConfigurationBase();
        Assert.assertEquals(actual.toString(), expected.toString());
    }

    @Test(description = "Loads a file path representation of the WSO2 specific config-base")
    public void testWSO2ConfigurationHome() {
        Path expected = Paths.get(CATALINA_BASE.toString(), Constants.TOMCAT_CONFIGURATION_DIRECTORY,
                Constants.APP_SERVER_CONFIGURATION_DIRECTORY);
        Path actual = PathUtils.getAppServerConfigurationBase();
        Assert.assertEquals(actual.toString(), expected.toString());
    }
}
