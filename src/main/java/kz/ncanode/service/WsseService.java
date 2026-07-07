package kz.ncanode.service;

import kz.ncanode.dto.request.WsseSignRequest;
import kz.ncanode.dto.response.VerificationResponse;
import kz.ncanode.dto.response.XmlSignResponse;
import kz.ncanode.exception.ClientException;
import kz.ncanode.exception.KeyException;
import kz.ncanode.exception.ServerException;
import kz.ncanode.wrapper.CertificateWrapper;
import kz.ncanode.wrapper.DocumentWrapper;
import kz.ncanode.wrapper.KalkanWrapper;
import kz.ncanode.wrapper.KeyStoreWrapper;
import kz.ncanode.wrapper.XMLSignatureWrapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.ws.security.components.crypto.CertificateStore;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.namespace.QName;
import javax.xml.soap.*;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;

/**
 * Сервис для работы с Wsse (Soap)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class WsseService {

    private final KalkanWrapper kalkanWrapper;
    private final XmlService xmlService;
    private final CertificateService certificateService;

    /**
     * Подписывает Wsse XML
     *
     * @param wsseSignRequest Запрос на подпись
     * @return Подписанный SOAP-конверт
     */
    public XmlSignResponse sign(final WsseSignRequest wsseSignRequest) {
        try {
            // read key
            final KeyStoreWrapper keystore = kalkanWrapper.read(wsseSignRequest.getKey(), wsseSignRequest.getKeyAlias(), wsseSignRequest.getPassword());
            final CertificateWrapper cert = keystore.getCertificate();

            // sign a soap request according to a reference implementation from smartbridge
            SOAPMessage msg = MessageFactory.newInstance().createMessage(null, new ByteArrayInputStream(
                xmlService.prepare(wsseSignRequest.getXml(), wsseSignRequest.isTrimXml()).getBytes(StandardCharsets.UTF_8)
            ));
            SOAPEnvelope env = msg.getSOAPPart().getEnvelope();
            SOAPBody body = env.getBody();

            String bodyId = "id-" + UUID.randomUUID();
            body.addAttribute(new QName(WSConstants.WSU_NS, "Id", WSConstants.WSU_PREFIX), bodyId);

            SOAPHeader header = env.getHeader();
            if (header == null) {
                header = env.addHeader();
            }

            Document doc = env.getOwnerDocument();

            Transforms transforms = new Transforms(env.getOwnerDocument());
            transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

            XMLSignatureWrapper signature = new XMLSignatureWrapper(doc, cert.getSignAlgorithmId(), Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

            signature.getXmlSignature().addDocument("#" + bodyId, transforms, cert.getHashAlgorithmId());
            signature.getXmlSignature().getSignedInfo().getSignatureMethodElement().setNodeValue(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.setMustUnderstand(true);
            secHeader.insertSecurityHeader();
            header.appendChild(secHeader.getSecurityHeaderElement());
            header.getFirstChild().appendChild(signature.getXmlSignature().getElement());

            SecurityTokenReference reference = new SecurityTokenReference(doc);
            reference.setKeyIdentifier(cert.getX509Certificate());

            signature.getXmlSignature().getKeyInfo().addUnknownElement(reference.getElement());
            signature.getXmlSignature().sign(keystore.getPrivateKey());



            try (StringWriter os = new StringWriter()) {
                TransformerFactory tf = TransformerFactory.newInstance();
                Transformer trans = tf.newTransformer();
                trans.transform(new DOMSource(doc), new StreamResult(os));

                return XmlSignResponse.builder()
                    .xml(os.toString())
                    .build();
            }
        } catch (KeyException e) {
            throw new ClientException(e.getMessage(), e);
        } catch (Exception e) {
            throw new ServerException(e.getMessage(), e);
        }
    }

    /**
     * Подписывает Wsse XML (v3) — аналог {@link #sign(WsseSignRequest)}, но с двумя отличиями,
     * чтобы точно повторить KalkanWrapper.signWsse из eds-cmd-example: у ds:Signature
     * проставляется случайный Id, а у wsse:Security нет атрибута mustUnderstand (используется
     * 3-аргументный конструктор WSSecHeader с mustUnderstand=false, как в eds-cmd-example, а не
     * setMustUnderstand(true)).
     *
     * @param wsseSignRequest Запрос на подпись
     * @return Подписанный SOAP-конверт
     */
    public XmlSignResponse signV3(final WsseSignRequest wsseSignRequest) {
        try {
            final KeyStoreWrapper keystore = kalkanWrapper.read(wsseSignRequest.getKey(), wsseSignRequest.getKeyAlias(), wsseSignRequest.getPassword());
            final String xml = xmlService.prepare(wsseSignRequest.getXml(), wsseSignRequest.isTrimXml());

            return XmlSignResponse.builder()
                .xml(signWsseEdsCompatible(xml, keystore))
                .build();
        } catch (KeyException e) {
            throw new ClientException(e.getMessage(), e);
        } catch (Exception e) {
            throw new ServerException(e.getMessage(), e);
        }
    }

    /**
     * В отличие от {@link #sign(WsseSignRequest)}, здесь не используется SAAJ (javax.xml.soap) —
     * весь документ, включая уже подписанный EDS-блок внутри data, парсится и сериализуется
     * обычным DOM (DocumentBuilderFactory/Transformer), тем же способом, каким уже подписывался
     * EDS-слой. SAAJ имеет свою собственную DOM-реализацию, которая при парсинге/сериализации
     * документа может переоформить текст base64-значений (DigestValue/SignatureValue) внутри уже
     * готовой EDS-подписи иначе, чем было при её вычислении — тогда байты SignedInfo меняются, и
     * подпись перестаёт проходить криптографическую проверку, хотя сам текст значения не менялся.
     * Даже eds-cmd-example, который использует SAAJ для этого шага, явно перепроверяет EDS-подпись
     * после WSSE-обёртывания в своём Main.java — то есть это известное слабое место, а не то, что
     * нужно копировать.
     */
    private String signWsseEdsCompatible(String xml, KeyStoreWrapper keystore) throws Exception {
        final CertificateWrapper cert = keystore.getCertificate();

        final DocumentWrapper documentWrapper = new DocumentWrapper(xml);
        final Document doc = documentWrapper.getDocument();
        final Element envelope = documentWrapper.getDocumentElement();
        final String soapNs = envelope.getNamespaceURI();

        final Element body = firstElementByTagNameNS(doc, soapNs, "Body");
        Element header = firstElementByTagNameNS(doc, soapNs, "Header");

        if (header == null) {
            header = doc.createElementNS(soapNs, qualify(envelope.getPrefix(), "Header"));
            envelope.insertBefore(header, envelope.getFirstChild());
        }

        String bodyId = "id-" + UUID.randomUUID();
        // setAttributeNS for a prefixed attribute does not create a real xmlns:wsu declaration
        // node on the live DOM - the Transformer only synthesizes one later, during serialization.
        // Apache Santuario's C14N walks the live tree during sign(), so without this the digest is
        // computed without xmlns:wsu, while eds-cmd-example re-parses the serialized XML (which by
        // then does have xmlns:wsu) and recomputes a different digest.
        body.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:" + WSConstants.WSU_PREFIX, WSConstants.WSU_NS);
        body.setAttributeNS(WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":Id", bodyId);
        body.setIdAttributeNS(WSConstants.WSU_NS, "Id", true);

        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

        XMLSignatureWrapper signature = new XMLSignatureWrapper(doc, cert.getSignAlgorithmId(), Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signature.getXmlSignature().setId(UUID.randomUUID().toString());

        signature.getXmlSignature().addDocument("#" + bodyId, transforms, cert.getHashAlgorithmId());
        signature.getXmlSignature().getSignedInfo().getSignatureMethodElement().setNodeValue(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

        WSSecHeader secHeader = new WSSecHeader(null, false, doc);
        secHeader.insertSecurityHeader();
        header.appendChild(secHeader.getSecurityHeaderElement());
        header.getFirstChild().appendChild(signature.getXmlSignature().getElement());

        SecurityTokenReference reference = new SecurityTokenReference(doc);
        reference.setKeyIdentifier(cert.getX509Certificate());

        signature.getXmlSignature().getKeyInfo().addUnknownElement(reference.getElement());
        signature.getXmlSignature().sign(keystore.getPrivateKey());

        return documentWrapper.toString();
    }

    private static String qualify(String prefix, String localName) {
        return (prefix == null || prefix.isEmpty()) ? localName : prefix + ":" + localName;
    }

    private static Element firstElementByTagNameNS(Document doc, String namespaceURI, String localName) {
        NodeList found = doc.getElementsByTagNameNS(namespaceURI, localName);
        return found.getLength() > 0 ? (Element) found.item(0) : null;
    }

    /**
     * Проверяет подписанный SOAP-конверт
     *
     * @param xml soap envelope
     * @param checkOcsp Проверять в OCSP
     * @param checkCrl Проверять в CRL
     * @return Результат проверки
     */
    public VerificationResponse verify(String xml, boolean checkOcsp, boolean checkCrl) {
        try {
            SOAPMessage msg = MessageFactory.newInstance().createMessage(null, new ByteArrayInputStream(
                xmlService.prepare(xml, false).getBytes(StandardCharsets.UTF_8)
            ));
            SOAPEnvelope env = msg.getSOAPPart().getEnvelope();
            Document doc = env.getOwnerDocument();

            Element root = (Element) doc.getFirstChild();
            NodeList signatures = root.getElementsByTagName("ds:Signature");

            if (signatures.getLength() < 1) {
                return VerificationResponse.builder()
                    .valid(false)
                    .signers(Collections.emptyList())
                    .build();
            }

            boolean valid = true;

            final ArrayList<CertificateWrapper> certs = new ArrayList<>();

            final Date currentDate = certificateService.getCurrentDate();

            Node sigNode = signatures.item(0);
            XMLSignature signature = new XMLSignature((Element) sigNode, "");
            NodeList securityRef = root.getElementsByTagName("wsse:SecurityTokenReference");
            SecurityTokenReference ref = new SecurityTokenReference((Element) securityRef.item(0));
            CertificateWrapper cert = new CertificateWrapper(ref.getKeyIdentifier(new CertificateStore(new X509Certificate[]{}))[0]);

            certificateService.attachValidationData(cert, checkOcsp, checkCrl);

            valid = signature.checkSignatureValue(cert.getPublicKey()) && cert.isValid(currentDate, checkOcsp, checkCrl);

            certs.add(cert);

            return VerificationResponse.builder()
                .valid(valid)
                .signers(certs.stream().map(c -> c.toCertificateInfo(currentDate, checkOcsp, checkCrl)).toList())
                .build();
        } catch (Exception e) {
            throw new ServerException(e.getMessage(), e);
        }
    }
}
