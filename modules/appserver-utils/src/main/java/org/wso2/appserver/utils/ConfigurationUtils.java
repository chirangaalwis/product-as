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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.IntStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

public class ConfigurationUtils {
    protected static Document loadDocument(Path path) throws AppServerException {
        //   TODO: pass the file through XSD.
        try {
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document document = dBuilder.parse(path.toFile());
            document.getDocumentElement().normalize();
            return document;
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new AppServerException("An error occurred during loading the " + path.toString() + " content.", e);
        }
    }

    protected static Set<String> loadMultipleSingleTypedElements(Document document, String elementTag) {
        NodeList list = document.getElementsByTagName(elementTag);
        Set<String> textContent = new HashSet<>();
        IntStream.range(0, list.getLength()).forEach(nodeValue -> {
            Node node = list.item(nodeValue);
            if ((node.getNodeType() == Node.ELEMENT_NODE)) {
                Element element = (Element) node;
                textContent.add(element.getTextContent());
            }
        });
        return textContent;
    }

    // TODO: Consider adding Optional
    protected static String loadSimpleTypeElement(Document document, String elementTag) {
        NodeList list = document.getElementsByTagName(elementTag);
        Node node = list.item(0);
        if (node != null) {
            return node.getTextContent();
        } else {
            return null;
        }
    }

    protected static void addKeyValuePairToMap(Map<String, Object> map, String key, String value) {
        Optional.ofNullable(map).ifPresent(
                dataStructure -> Optional.ofNullable(value).ifPresent(stringValue -> dataStructure.put(key, value)));
    }
}
