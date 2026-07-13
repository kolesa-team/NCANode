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
import org.w3c.dom.NodeList;
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

    private static final String DS_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#";

    // Фабрики JAXP не потокобезопасны, а их newInstance() дорог (service discovery через
    // classloader). Держим по одному сконфигурированному экземпляру на поток, чтобы не создавать
    // их на каждый парсинг/сериализацию и при этом не разделять между потоками.
    private static final ThreadLocal<DocumentBuilderFactory> DOCUMENT_BUILDER_FACTORY =
        ThreadLocal.withInitial(() -> {
            final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            return factory;
        });

    private static final ThreadLocal<XPathFactory> XPATH_FACTORY =
        ThreadLocal.withInitial(XPathFactory::newInstance);

    private static final ThreadLocal<TransformerFactory> TRANSFORMER_FACTORY =
        ThreadLocal.withInitial(TransformerFactory::newInstance);

    private final Document document;

    public DocumentWrapper(String xmlStr) {
        try {
            final DocumentBuilder documentBuilder = DOCUMENT_BUILDER_FACTORY.get().newDocumentBuilder();

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
     * элемент, найденный по xpath, вырезается в отдельный Document, сериализуется в строку и парсится обратно ДО подписи
     * (см. {@link #extractToStandaloneDocument}). Этот шаг обязателен: он материализует namespace-декларации, унаследованные от предков в
     * исходном документе (например xmlns:xsi), на теперь-самостоятельном элементе, поскольку обычный
     * сериализатор обязан объявлять используемые namespace, чтобы фрагмент был well-formed сам по
     * себе. Без этого шага дайджест считается по другим байтам, и подпись не проходит проверку.
     * Затем элемент подписывается (self-reference, Id генерируется при необходимости, ds:Signature
     * вкладывается внутрь), после чего подписанный элемент импортируется на место оригинала в исходном документе.
     * Алгоритмы канонизации/трансформа — SignedInfo exclusive-no-comments, Reference inclusive-with-comments.
     */
    public void createXmlSignatureExtracted(CertificateWrapper certificateWrapper, PrivateKey privateKey, String xpath) {
        final Element original = resolveInsertionPoint(xpath);
        stripWhitespace(original);

        final DocumentWrapper signedWrapper = extractToStandaloneDocument(original);
        signedWrapper.createSelfReferencingXmlSignature(certificateWrapper).sign(privateKey);

        final Node importedSigned = getDocument().importNode(signedWrapper.getDocumentElement(), true);
        original.getParentNode().replaceChild(importedSigned, original);
    }

    /**
     * Возвращает по одной {@link XMLSignatureWrapper} на каждый ds:Signature в документе,
     * подготовленной к проверке v2-подписи (см. {@link #createXmlSignatureExtracted}): элемент,
     * внутри которого лежит подпись, извлекается в отдельный документ тем же способом, что и при
     * подписи (сериализация + повторный парсинг), после чего его Id регистрируется как ID-тип,
     * чтобы ds:Reference "#id" резолвился. Извлечение обязательно: ds:Reference в v2 использует
     * inclusive canonicalization и потому чувствителен к namespace-декларациям предков, которых
     * в отдельно стоящем элементе нет — ровно как при подписи. Проверка "на месте" (в исходном
     * документе) для такой подписи дала бы ложный digest mismatch.
     */
    public List<XMLSignatureWrapper> signaturesForVerification() {
        final NodeList signatures = getDocumentElement().getElementsByTagNameNS(DS_NAMESPACE, "Signature");
        final List<Element> hosts = new ArrayList<>();

        // снимок host-элементов (родитель каждой подписи) до извлечения, т.к. NodeList живой
        for (int i = 0; i < signatures.getLength(); i++) {
            final Node parent = signatures.item(i).getParentNode();
            hosts.add(parent instanceof Element ? (Element) parent : getDocumentElement());
        }

        final List<XMLSignatureWrapper> result = new ArrayList<>();

        for (Element host : hosts) {
            final DocumentWrapper standalone = extractToStandaloneDocument(host);
            final NodeList standaloneSignatures = standalone.getDocumentElement().getElementsByTagNameNS(DS_NAMESPACE, "Signature");

            if (standaloneSignatures.getLength() < 1) {
                continue;
            }

            final Element signature = (Element) standaloneSignatures.item(0);
            standalone.registerReferenceIdAttribute(signature);
            result.add(new XMLSignatureWrapper(signature));
        }

        return result;
    }

    /**
     * Изолирует элемент: копирует его в отдельный Document, сериализует и парсит обратно.
     * Повторный парсинг материализует namespace-декларации, унаследованные от предков в исходном
     * документе, на теперь-самостоятельном элементе (обычный сериализатор обязан объявлять
     * используемые namespace, чтобы фрагмент был well-formed сам по себе). Это тот самый вид
     * элемента, по которому в v2 считается дайджест и при подписи, и при проверке.
     */
    private static DocumentWrapper extractToStandaloneDocument(Element element) {
        try {
            final Document extractedDocument = DOCUMENT_BUILDER_FACTORY.get().newDocumentBuilder().newDocument();
            extractedDocument.appendChild(extractedDocument.importNode(element, true));

            return new DocumentWrapper(new DocumentWrapper(extractedDocument).toString());
        } catch (ParserConfigurationException e) {
            log.error("XML generation error", e);
            throw new ServerException("XML generation error", e);
        }
    }

    /**
     * Находит ds:Reference подписи и регистрирует элемент, на который он ссылается (по атрибуту
     * Id), как ID-тип через DOM, чтобы Apache Santuario мог разрешить ссылку "#id" при проверке
     * дайджеста без DTD/ATTLIST.
     */
    private void registerReferenceIdAttribute(Element signature) {
        final NodeList references = signature.getElementsByTagNameNS(DS_NAMESPACE, "Reference");

        if (references.getLength() < 1) {
            return;
        }

        final String uri = ((Element) references.item(0)).getAttribute("URI");

        if (uri == null || !uri.startsWith("#") || uri.length() < 2) {
            return;
        }

        registerIdAttribute(getDocumentElement(), uri.substring(1));
    }

    private void registerIdAttribute(Element element, String id) {
        final Node idAttr = element.getAttributeNode("Id");

        if (idAttr != null && id.equals(element.getAttribute("Id"))) {
            element.setIdAttributeNode(element.getAttributeNode("Id"), true);
            return;
        }

        final NodeList children = element.getChildNodes();

        for (int i = 0; i < children.getLength(); i++) {
            final Node child = children.item(i);

            if (child instanceof Element) {
                registerIdAttribute((Element) child, id);
            }
        }
    }

    private void stripWhitespace(Element element) {
        final DocumentTraversal traversal = (DocumentTraversal) getDocument();
        final NodeIterator it = traversal.createNodeIterator(element, NodeFilter.SHOW_TEXT, null, true);
        final List<Node> toRemove = new ArrayList<>();

        for (Node n = it.nextNode(); n != null; n = it.nextNode()) {
            if (n.getNodeValue().trim().isEmpty() && !isInsideSignature(n, element)) {
                toRemove.add(n);
            }
        }

        for (Node n : toRemove) {
            n.getParentNode().removeChild(n);
        }
    }

    /**
     * Проверяет, лежит ли узел внутри уже существующего ds:Signature (между собой и boundary).
     * Нужно, чтобы {@link #stripWhitespace} не удалял пробельные узлы внутри подписей, которые
     * уже есть в подписываемом элементе (например, добавленных предыдущим signer'ом или пришедших
     * во входном документе): их SignedInfo форматируется с переносами строк, значимыми для
     * канонизации, и удаление этих узлов сломало бы такую подпись.
     */
    private boolean isInsideSignature(Node node, Element boundary) {
        for (Node p = node.getParentNode(); p != null && p != boundary; p = p.getParentNode()) {
            if (p.getNodeType() == Node.ELEMENT_NODE
                && "Signature".equals(p.getLocalName())
                && DS_NAMESPACE.equals(p.getNamespaceURI())) {
                return true;
            }
        }

        return false;
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
     * Находит элемент, указанный xpath. Если xpath не задан (пустой), возвращается корневой
     * элемент документа. XPath вычисляется без NamespaceContext, поэтому namespace-префиксы не
     * поддерживаются — используйте форму через local-name(). Если выражение совпадает с
     * несколькими узлами, возвращается первый в порядке документа (XPathConstants.NODE).
     */
    private Element resolveInsertionPoint(String xpath) {
        if (xpath == null || xpath.isBlank()) {
            return getDocumentElement();
        }

        final Node node;

        try {
            node = (Node) XPATH_FACTORY.get().newXPath().evaluate(xpath, getDocument(), XPathConstants.NODE);
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
            Transformer transformer = TRANSFORMER_FACTORY.get().newTransformer();
            transformer.transform(new DOMSource(getDocument()), new StreamResult(stringWriter));
            return stringWriter.toString();
        } catch (IOException | TransformerException e) {
            log.error("XML generation error", e);
            throw new ServerException("XML generation error", e);
        }
    }
}
