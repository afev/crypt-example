package service;

import com.objsys.asn1j.runtime.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.CryptoPro.JCP.ASN.CertificateExtensions.GeneralName;
import ru.CryptoPro.JCP.ASN.CertificateExtensions.GeneralNames;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.*;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.*;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.params.OID;
import ru.CryptoPro.JCSP.JCSP;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Signature;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;

public class Signer {
    private static final Logger log = LoggerFactory.getLogger(Signer.class);

    public void initSecurityContext() {
        Security.removeProvider(JCSP.PROVIDER_NAME);
        Security.addProvider(new JCSP());
    }

    public PrivateKeyContext getPrivateKey() throws Exception {
        String alias = "extAuth3";
        KeyStore keyStore = getKeyStore();
        java.security.cert.Certificate certificate = keyStore.getCertificate(alias);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
        return new PrivateKeyContext(privateKey, certificate);
    }

    private KeyStore getKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("MY", JCSP.PROVIDER_NAME);
        keyStore.load(null, null);
        return keyStore;
    }

    public byte[] signPkcs7(PrivateKeyContext keyContext) {
        byte[] attachment;
        try (InputStream resourceAsStream = this.getClass().getClassLoader().getResourceAsStream("file.txt")) {
            attachment = resourceAsStream.readAllBytes();
            if (attachment.length == 0) {
                log.debug("Document has an empty attachment, attachment.length == 0");
                return new byte[0];
            }
            PrivateKey[] keys = new PrivateKey[1];
            keys[0] = keyContext.getKey();
            Certificate[] certificates = new Certificate[1];
            certificates[0] = keyContext.getCertificate();

            return Base64.getEncoder().encode(createHashCMSEx(attachment, keys, certificates));

        } catch (Exception e) {
            e.printStackTrace();
            return new byte[0];
        }

    }

    private byte[] createHashCMSEx(byte[] content, PrivateKey[] keys, Certificate[] certs) throws Exception {
        final var digestOid = JCP.GOST_DIGEST_2012_256_OID;
        final var signOid = JCP.GOST_PARAMS_SIG_2012_256_KEY_OID;

        //create hashCMS
        final ContentInfo all = new ContentInfo();
        all.contentType = new Asn1ObjectIdentifier(new OID(CMStools.STR_CMS_OID_SIGNED).value);

        final SignedData cms = new SignedData();
        all.content = cms;
        cms.version = new CMSVersion(1);

        // digest
        cms.digestAlgorithms = new DigestAlgorithmIdentifiers(1);
        final DigestAlgorithmIdentifier a = new DigestAlgorithmIdentifier(new OID(digestOid).value);
        a.parameters = new Asn1Null();
        cms.digestAlgorithms.elements[0] = a;

        cms.encapContentInfo = new EncapsulatedContentInfo(
                new Asn1ObjectIdentifier(new OID(CMStools.STR_CMS_OID_DATA).value), null);

        // certificates
        final int nCerts = certs.length;
        cms.certificates = new CertificateSet(nCerts);
        cms.certificates.elements = new CertificateChoices[nCerts];

        for (int i = 0; i < cms.certificates.elements.length; i++) {

            final ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate certificate =
                    new ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate();
            final Asn1BerDecodeBuffer decodeBuffer = new Asn1BerDecodeBuffer(certs[i].getEncoded());
            certificate.decode(decodeBuffer);

            cms.certificates.elements[i] = new CertificateChoices();
            cms.certificates.elements[i].set_certificate(certificate);
        }

        // Signature.getInstance
        final Signature signature = Signature.getInstance(JCP.GOST_SIGN_2012_256_NAME, JCSP.PROVIDER_NAME);
        byte[] sign;

        // signer infos
        final int nsign = keys.length;
        cms.signerInfos = new SignerInfos(nsign);
        for (int i = 0; i < cms.signerInfos.elements.length; i++) {

            cms.signerInfos.elements[i] = new SignerInfo();
            cms.signerInfos.elements[i].version = new CMSVersion(1);
            cms.signerInfos.elements[i].sid = new SignerIdentifier();

            final byte[] encodedName = ((X509Certificate) certs[i]).getIssuerX500Principal().getEncoded();
            final Asn1BerDecodeBuffer nameBuf = new Asn1BerDecodeBuffer(encodedName);
            final Name name = new Name();
            name.decode(nameBuf);

            final CertificateSerialNumber num = new CertificateSerialNumber(((X509Certificate) certs[i]).getSerialNumber());
            cms.signerInfos.elements[i].sid.set_issuerAndSerialNumber(new IssuerAndSerialNumber(name, num));
            cms.signerInfos.elements[i].digestAlgorithm = new DigestAlgorithmIdentifier(new OID(digestOid).value);
            cms.signerInfos.elements[i].digestAlgorithm.parameters = new Asn1Null();
            cms.signerInfos.elements[i].signatureAlgorithm = new SignatureAlgorithmIdentifier(new OID(signOid).value);
            cms.signerInfos.elements[i].signatureAlgorithm.parameters = new Asn1Null();

            //signedAttributes
            cms.signerInfos.elements[i].signedAttrs = new SignedAttributes(4);

            //-contentType
            int k = 0;
            cms.signerInfos.elements[i].signedAttrs.elements[k] =
                    new Attribute(new OID(CMStools.STR_CMS_OID_CONT_TYP_ATTR).value, new Attribute_values(1));
            final Asn1Type conttype = new Asn1ObjectIdentifier(new OID(CMStools.STR_CMS_OID_DATA).value);
            cms.signerInfos.elements[i].signedAttrs.elements[k].values.elements[0] = conttype;

            //-Time
            k += 1;
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(new Date());

            cms.signerInfos.elements[i].signedAttrs.elements[k] =
                    new Attribute(new OID(CMStools.STR_CMS_OID_SIGN_TYM_ATTR).value, new Attribute_values(1));
            final Time time = new Time();
            final Asn1UTCTime utcTime = new Asn1UTCTime();
            utcTime.setTime(calendar);
            time.set_utcTime(utcTime);
            cms.signerInfos.elements[i].signedAttrs.elements[k].values.elements[0] = time.getElement();

            //-message digest
            k += 1;
            cms.signerInfos.elements[i].signedAttrs.elements[k] =
                    new Attribute(new OID(CMStools.STR_CMS_OID_DIGEST_ATTR).value, new Attribute_values(1));
            final byte[] messageDigestBlob = digestm(content);
            final Asn1Type messageDigest = new Asn1OctetString(messageDigestBlob);
            cms.signerInfos.elements[i].signedAttrs.elements[k].values.elements[0] = messageDigest;

            k += 1;
            cms.signerInfos.elements[i].signedAttrs.elements[k] =
                    new Attribute(new OID(ALL_PKIX1Explicit88Values.id_aa_signingCertificateV2).value, new Attribute_values(1));

            final DigestAlgorithmIdentifier digestAlgorithmIdentifier = new DigestAlgorithmIdentifier(new OID(digestOid).value);

            // Хеш сертификата ключа подписи.
            final CertHash certHash = new CertHash(digestm(certs[i].getEncoded()));

            // Issuer name из сертификата ключа подписи.
            GeneralName generalName = new GeneralName();
            generalName.set_directoryName(name);

            GeneralNames generalNames = new GeneralNames();
            generalNames.elements = new GeneralName[1];
            generalNames.elements[0] = generalName;

            // Комбинируем издателя и серийный номер.
            IssuerSerial issuerSerial = new IssuerSerial(generalNames, num);
            ESSCertIDv2 essCertIDv2 = new ESSCertIDv2(digestAlgorithmIdentifier, certHash, issuerSerial);

            _SeqOfESSCertIDv2 essCertIDv2s = new _SeqOfESSCertIDv2(1);
            essCertIDv2s.elements = new ESSCertIDv2[1];
            essCertIDv2s.elements[0] = essCertIDv2;

            SigningCertificateV2 signingCertificateV2 = new SigningCertificateV2(essCertIDv2s);
            cms.signerInfos.elements[i].signedAttrs.elements[k].values.elements[0] = signingCertificateV2;


            //signature
            Asn1BerEncodeBuffer encBufSignedAttr = new Asn1BerEncodeBuffer();
            cms.signerInfos.elements[i].signedAttrs.encode(encBufSignedAttr);
            final byte[] hsign = encBufSignedAttr.getMsgCopy();

            signature.initSign(keys[i]);
            signature.update(hsign);
            sign = signature.sign();
            log.info("sign id {}", signature.hashCode());
            cms.signerInfos.elements[i].signature = new SignatureValue(sign);
        }

        // encode
        final Asn1BerEncodeBuffer asnBuf = new Asn1BerEncodeBuffer();
        all.encode(asnBuf, true);
        return asnBuf.getMsgCopy();
    }

    private byte[] digestm(byte[] bytes) throws Exception {
        // calculation messageDigest
        final ByteArrayInputStream stream = new ByteArrayInputStream(bytes);
        final java.security.MessageDigest digest =
                java.security.MessageDigest.getInstance(JCP.GOST_DIGEST_2012_256_NAME, JCSP.PROVIDER_NAME);

        final DigestInputStream digestStream = new DigestInputStream(stream, digest);
        while (digestStream.available() != 0) digestStream.read();
        return digest.digest();
    }

}
