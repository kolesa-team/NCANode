package kz.ncanode.wrapper;

import kz.ncanode.exception.ServerException;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.encryption.XMLCipherParameters;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Optional;

@Slf4j
@Getter
@RequiredArgsConstructor
public class DocumentWrapper {
    private final Document document;

    public DocumentWrapper(String xmlStr) {
        try {
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);

            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();

            try(ByteArrayInputStream xmlStream = new ByteArrayInputStream(xmlStr.trim().getBytes(StandardCharsets.UTF_8))) {
                document = documentBuilder.parse(xmlStream);
                Objects.requireNonNull(document);
            }
        } catch (ParserConfigurationException | IOException | SAXException e) {
            log.error("XML parsing error", e);
            throw new ServerException("Cannot read XML", e);
        }
    }

    public Element getDocumentElement() {
        return document.getDocumentElement();
    }

    private static final String[] ID_ATTRIBUTE_NAMES = {"Id", "ID", "id"};

    /**
     * Создает и добавляет XMLDSIG подпись
     * @return XML Signature Wrapper
     */
    public XMLSignatureWrapper createXmlSignature(CertificateWrapper certificateWrapper, String referenceUri, boolean insertSignatureAtReference) {
        final XMLSignatureWrapper sig = new XMLSignatureWrapper(getDocument(), certificateWrapper.getSignAlgorithmId());
        final Element insertionPoint = insertSignatureAtReference ? resolveInsertionPoint(referenceUri) : getDocumentElement();
        insertionPoint.appendChild(sig.getXmlSignature().getElement());
        Transforms transforms = new Transforms(getDocument());

        try {
            transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
            transforms.addTransform(XMLCipherParameters.N14C_XML_CMMNTS);
            sig.getXmlSignature().addDocument(Optional.ofNullable(referenceUri).orElse(""), transforms, certificateWrapper.getHashAlgorithmId());
            sig.getXmlSignature().addKeyInfo(certificateWrapper.getX509Certificate());
        } catch (XMLSecurityException e) {
            log.error("XMLDSig Signature creation error", e);
            throw new ServerException("XMLDSig Signature creation error", e);
        }

        return sig;
    }

    /**
     * Определяет, куда вставлять узел ds:Signature. Если referenceUri указывает на конкретный
     * элемент (вида "#id"), подпись вкладывается внутрь этого элемента (enveloped signature),
     * а найденный id-атрибут регистрируется как ID, чтобы Apache Santuario мог разрешить
     * ссылку "#id" при вычислении дайджеста без необходимости в DTD/ATTLIST.
     * Иначе подпись добавляется в конец корневого элемента, как раньше.
     */
    private Element resolveInsertionPoint(String referenceUri) {
        if (referenceUri == null || !referenceUri.startsWith("#") || referenceUri.length() < 2) {
            return getDocumentElement();
        }

        return findElementById(getDocumentElement(), referenceUri.substring(1)).orElse(getDocumentElement());
    }

    private Optional<Element> findElementById(Element element, String id) {
        NamedNodeMap attributes = element.getAttributes();

        for (int i = 0; i < attributes.getLength(); i++) {
            Attr attr = (Attr) attributes.item(i);
            String attrName = attr.getLocalName() != null ? attr.getLocalName() : attr.getName();

            for (String idAttributeName : ID_ATTRIBUTE_NAMES) {
                if (idAttributeName.equals(attrName) && id.equals(attr.getValue())) {
                    element.setIdAttributeNode(attr, true);
                    return Optional.of(element);
                }
            }
        }

        NodeList children = element.getChildNodes();

        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);

            if (child instanceof Element) {
                Optional<Element> found = findElementById((Element) child, id);

                if (found.isPresent()) {
                    return found;
                }
            }
        }

        return Optional.empty();
    }

    @Override
    public String toString() {
        try (StringWriter stringWriter = new StringWriter()) {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.transform(new DOMSource(getDocument()), new StreamResult(stringWriter));
            return stringWriter.toString();
        } catch (IOException | TransformerException e) {
            log.error("XML generation error", e);
            throw new ServerException("XML generation error", e);
        }
    }
}
