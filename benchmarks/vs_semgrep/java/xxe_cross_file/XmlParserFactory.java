package com.example.xxe;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

public class XmlParserFactory {

    public static SAXParser createParser() throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        // Developer "forgot" to disable external entities
        // factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return factory.newSAXParser();
    }
}
