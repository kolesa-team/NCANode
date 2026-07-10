package kz.ncanode.wrapper;

import kz.ncanode.exception.ClientException;
import kz.ncanode.exception.ServerException;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.encryption.XMLCipherParameters;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.traversal.DocumentTraversal;
import org.w3c.dom.traversal.NodeFilter;
import org.w3c.dom.traversal.NodeIterator;
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
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

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

        return signReference(sig, certificateWrapper, referenceUri, XMLCipherParameters.N14C_XML_CMMNTS);
    }

    /**
     * Создает и добавляет XMLDSIG подпись в корневой элемент документа,
     * если у корневого элемента нет атрибута Id, он генерируется
     * (UUID), и Reference URI выставляется как "#" + этот Id. ds:Signature получает
     * собственный случайный Id. Для ds:CanonicalizationMethod у SignedInfo используется
     * exclusive canonicalization. Трансформ канонизации у самой ds:Reference — всегда
     * inclusive-with-comments
     * @return XML Signature Wrapper
     */
    private XMLSignatureWrapper createSelfReferencingXmlSignature(CertificateWrapper certificateWrapper) {
        final Element insertionPoint = getDocumentElement();
        final String referenceUri = "#" + ensureIdAttribute(insertionPoint);

        final XMLSignatureWrapper sig = new XMLSignatureWrapper(getDocument(), certificateWrapper.getSignAlgorithmId(), Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        sig.getXmlSignature().setId(UUID.randomUUID().toString());
        insertionPoint.appendChild(sig.getXmlSignature().getElement());

        return signReference(sig, certificateWrapper, referenceUri, XMLCipherParameters.N14C_XML_CMMNTS);
    }

    /**
     * элемент, найденный по xpath, вырезается в отдельный Document, сериализуется в строку и парсится обратно ДО подписи.
     * этот шаг обязателен: он материализует namespace-декларации, унаследованные от предков в исходном
     * документе (например xmlns:xsi), на теперь-самостоятельном элементе, поскольку обычный
     * сериализатор обязан объявлять используемые namespace, чтобы фрагмент был well-formed сам по
     * себе. Без этого шага дайджест считается по другим байтам, и подпись не проходит проверку.
     * Затем элемент подписывается (self-reference, Id генерируется
     * при необходимости, ds:Signature вкладывается внутрь), результат снова сериализуется в
     * строку и парсится обратно, после чего подписанный элемент
     * вставляется на место оригинала в исходном документе.
     * Алгоритмы канонизации/трансформа — SignedInfo exclusive-no-comments, Reference inclusive-with-comments.
     */
    public void createXmlSignatureExtracted(CertificateWrapper certificateWrapper, PrivateKey privateKey, String xpath) {
        final Element original = resolveInsertionPoint(xpath);
        stripWhitespace(original);

        try {
            final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);

            final Document extractedDocument = documentBuilderFactory.newDocumentBuilder().newDocument();
            extractedDocument.appendChild(extractedDocument.importNode(original, true));

            final DocumentWrapper preSignWrapper = new DocumentWrapper(new DocumentWrapper(extractedDocument).toString());
            preSignWrapper.createSelfReferencingXmlSignature(certificateWrapper).sign(privateKey);

            final DocumentWrapper signedWrapper = new DocumentWrapper(preSignWrapper.toString());
            final Node importedSigned = getDocument().importNode(signedWrapper.getDocumentElement(), true);

            original.getParentNode().replaceChild(importedSigned, original);
        } catch (ParserConfigurationException e) {
            log.error("XML generation error", e);
            throw new ServerException("XML generation error", e);
        }
    }

    private void stripWhitespace(Element element) {
        final DocumentTraversal traversal = (DocumentTraversal) getDocument();
        final NodeIterator it = traversal.createNodeIterator(element, NodeFilter.SHOW_TEXT, null, true);
        final List<Node> toRemove = new ArrayList<>();

        for (Node n = it.nextNode(); n != null; n = it.nextNode()) {
            if (n.getNodeValue().trim().isEmpty()) {
                toRemove.add(n);
            }
        }

        for (Node n : toRemove) {
            n.getParentNode().removeChild(n);
        }
    }

    private String ensureIdAttribute(Element element) {
        String id = element.getAttribute("Id");

        if (id.isEmpty()) {
            id = UUID.randomUUID().toString();
            element.setAttribute("Id", id);
        }

        element.setIdAttributeNode(element.getAttributeNode("Id"), true);

        return id;
    }

    private XMLSignatureWrapper signReference(XMLSignatureWrapper sig, CertificateWrapper certificateWrapper, String referenceUri, String c14nAlgorithm) {
        Transforms transforms = new Transforms(getDocument());

        try {
            transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
            transforms.addTransform(c14nAlgorithm);
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
