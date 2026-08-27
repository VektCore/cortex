// Intentionally vulnerable: XXE.
// CWE-611: XML External Entity (XXE) Reference.
using System.IO;
using System.Xml;

namespace KassandraSastDemo
{
    public class XmlParser
    {
        // VULNERABILITY: XXE — default XmlReaderSettings allow DTD processing
        public XmlDocument ParseXml(string xmlString)
        {
            var doc = new XmlDocument
            {
                // BAD: enabling DTD parsing opens XXE
                XmlResolver = new XmlUrlResolver()
            };
            doc.LoadXml(xmlString);
            return doc;
        }

        // VULNERABILITY: XXE via XmlReader with DtdProcessing.Parse
        public string ReadXmlStream(Stream stream)
        {
            var settings = new XmlReaderSettings
            {
                // BAD: DtdProcessing.Parse + XmlUrlResolver = XXE
                DtdProcessing = DtdProcessing.Parse,
                XmlResolver = new XmlUrlResolver()
            };
            using var reader = XmlReader.Create(stream, settings);
            return reader.ReadOuterXml();
        }

        // SECURE EXAMPLE: disable DTD and external resolution
        public XmlDocument ParseXmlSecure(string xmlString)
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null
            };
            using var reader = XmlReader.Create(new StringReader(xmlString), settings);
            var doc = new XmlDocument { XmlResolver = null };
            doc.Load(reader);
            return doc;
        }
    }
}
