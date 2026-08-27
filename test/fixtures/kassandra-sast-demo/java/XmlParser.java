package com.example.vulnerable;

import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;
import org.w3c.dom.*;
import org.xml.sax.*;
import java.io.*;

/**
 * XML Parser with XXE vulnerabilities.
 * CWE-611: XML External Entity (XXE) Injection
 * Severity: HIGH
 */
public class XmlParser {

    // VULNERABILITY: XXE via DocumentBuilder
    public Document parseXmlString(String xmlString) throws Exception {
        // BAD: Default DocumentBuilderFactory allows XXE
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();

        // Attack payload:
        // <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        // <data>&xxe;</data>
        return builder.parse(new InputSource(new StringReader(xmlString)));
    }

    // VULNERABILITY: XXE via SAXParser
    public void parseWithSax(String xmlString, DefaultHandler handler) throws Exception {
        // BAD: SAXParser allows XXE by default
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser parser = factory.newSAXParser();
        parser.parse(new InputSource(new StringReader(xmlString)), handler);
    }

    // VULNERABILITY: XXE via XMLReader
    public void parseWithReader(String xmlString) throws Exception {
        // BAD: XMLReader allows XXE
        XMLReader reader = XMLReaderFactory.createXMLReader();
        reader.parse(new InputSource(new StringReader(xmlString)));
    }

    // VULNERABILITY: XXE via TransformerFactory
    public String transformXml(String xmlString, String xsltString) throws Exception {
        // BAD: TransformerFactory allows XXE
        TransformerFactory factory = TransformerFactory.newInstance();

        Source xslt = new StreamSource(new StringReader(xsltString));
        Transformer transformer = factory.newTransformer(xslt);

        Source xml = new StreamSource(new StringReader(xmlString));
        StringWriter writer = new StringWriter();
        transformer.transform(xml, new StreamResult(writer));

        return writer.toString();
    }

    // VULNERABILITY: XXE via SchemaFactory
    public void validateWithSchema(String xmlString, String schemaString) throws Exception {
        // BAD: SchemaFactory allows XXE
        javax.xml.validation.SchemaFactory factory =
            javax.xml.validation.SchemaFactory.newInstance(
                javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI
            );

        javax.xml.validation.Schema schema = factory.newSchema(
            new StreamSource(new StringReader(schemaString))
        );

        javax.xml.validation.Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader(xmlString)));
    }

    // VULNERABILITY: SSRF via XXE
    public Document parseFromUrl(String url) throws Exception {
        // BAD: Fetching external XML allows SSRF
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();

        // Attack: url = "http://internal-server/secret"
        return builder.parse(url);
    }

    // SECURE EXAMPLE: Disable XXE in DocumentBuilder
    public Document parseXmlSecure(String xmlString) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

        // GOOD: Disable XXE
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);

        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new InputSource(new StringReader(xmlString)));
    }

    // SECURE EXAMPLE: Disable XXE in SAXParser
    public void parseWithSaxSecure(String xmlString, DefaultHandler handler) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();

        // GOOD: Disable XXE features
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

        SAXParser parser = factory.newSAXParser();
        parser.parse(new InputSource(new StringReader(xmlString)), handler);
    }

    // SECURE EXAMPLE: Safe TransformerFactory
    public String transformXmlSecure(String xmlString, String xsltString) throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();

        // GOOD: Disable external access
        factory.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");

        Source xslt = new StreamSource(new StringReader(xsltString));
        Transformer transformer = factory.newTransformer(xslt);

        Source xml = new StreamSource(new StringReader(xmlString));
        StringWriter writer = new StringWriter();
        transformer.transform(xml, new StreamResult(writer));

        return writer.toString();
    }
}
