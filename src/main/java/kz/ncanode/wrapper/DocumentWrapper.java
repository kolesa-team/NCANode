package kz.ncanode.wrapper;

import kz.ncanode.exception.ClientException;
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
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
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

    /**
     * Создает и добавляет XMLDSIG подпись в конец корневого элемента документа
     * @return XML Signature Wrapper
     */
    public XMLSignatureWrapper createXmlSignature(CertificateWrapper certificateWrapper, String referenceUri) {
        final XMLSignatureWrapper sig = new XMLSignatureWrapper(getDocument(), certificateWrapper.getSignAlgorithmId());
        getDocumentElement().appendChild(sig.getXmlSignature().getElement());

        return signReference(sig, certificateWrapper, referenceUri);
    }

    /**
     * Создает и добавляет XMLDSIG подпись внутрь элемента, на который указывает xpath.
     * Дополнительно резолвит referenceUri вида "#id" по атрибутам Id/ID/id, регистрируя
     * найденный атрибут как ID через DOM, чтобы Apache Santuario мог разрешить ссылку
     * при вычислении дайджеста без необходимости в DTD/ATTLIST.
     * @return XML Signature Wrapper
     */
    public XMLSignatureWrapper createXmlSignatureAtXPath(CertificateWrapper certificateWrapper, String referenceUri, String xpath) {
        registerReferenceIdAttribute(referenceUri);

        final XMLSignatureWrapper sig = new XMLSignatureWrapper(getDocument(), certificateWrapper.getSignAlgorithmId());
        resolveInsertionPoint(xpath).appendChild(sig.getXmlSignature().getElement());

        return signReference(sig, certificateWrapper, referenceUri);
    }

    private XMLSignatureWrapper signReference(XMLSignatureWrapper sig, CertificateWrapper certificateWrapper, String referenceUri) {
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
     * Определяет, куда вставлять узел ds:Signature. Если задан xpath, подпись вкладывается
     * внутрь элемента, на который он указывает (enveloped signature). Иначе подпись
     * добавляется в конец корневого элемента, как раньше.
     */
    private Element resolveInsertionPoint(String xpath) {
        if (xpath == null || xpath.isBlank()) {
            return getDocumentElement();
        }

        final Node node;

        try {
            node = (Node) XPathFactory.newInstance().newXPath().evaluate(xpath, getDocument(), XPathConstants.NODE);
        } catch (XPathExpressionException e) {
            throw new ClientException("Invalid xpath expression: " + xpath);
        }

        if (!(node instanceof Element)) {
            throw new ClientException("xpath does not resolve to an element: " + xpath);
        }

        return (Element) node;
    }

    /**
     * Если referenceUri указывает на конкретный элемент (вида "#id"), находит его по атрибуту
     * Id и регистрирует найденный атрибут как ID через DOM, чтобы Apache Santuario мог
     * разрешить ссылку "#id" при вычислении дайджеста без необходимости в DTD/ATTLIST.
     */
    private void registerReferenceIdAttribute(String referenceUri) {
        if (referenceUri == null || !referenceUri.startsWith("#") || referenceUri.length() < 2) {
            return;
        }

        findElementById(getDocumentElement(), referenceUri.substring(1));
    }

    private Optional<Element> findElementById(Element element, String id) {
        NamedNodeMap attributes = element.getAttributes();

        for (int i = 0; i < attributes.getLength(); i++) {
            Attr attr = (Attr) attributes.item(i);
            String attrName = attr.getLocalName() != null ? attr.getLocalName() : attr.getName();

            if ("Id".equals(attrName) && id.equals(attr.getValue())) {
                element.setIdAttributeNode(attr, true);
                return Optional.of(element);
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
