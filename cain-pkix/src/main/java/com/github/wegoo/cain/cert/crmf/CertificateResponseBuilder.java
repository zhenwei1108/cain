package com.github.wegoo.cain.cert.crmf;

import com.github.wegoo.cain.asn1.ASN1Integer;
import com.github.wegoo.cain.asn1.ASN1OctetString;
import com.github.wegoo.cain.asn1.DEROctetString;
import com.github.wegoo.cain.asn1.cmp.CMPCertificate;
import com.github.wegoo.cain.asn1.cmp.CertOrEncCert;
import com.github.wegoo.cain.asn1.cmp.CertResponse;
import com.github.wegoo.cain.asn1.cmp.CertifiedKeyPair;
import com.github.wegoo.cain.asn1.cmp.PKIStatusInfo;
import com.github.wegoo.cain.asn1.cms.EnvelopedData;
import com.github.wegoo.cain.asn1.crmf.EncryptedKey;
import com.github.wegoo.cain.cert.X509CertificateHolder;
import com.github.wegoo.cain.cms.CMSEnvelopedData;

/**
 * Builder for CertificateResponse objects (the CertResponse CRMF equivalent).
 */
public class CertificateResponseBuilder
{
    private final ASN1Integer certReqId;
    private final PKIStatusInfo statusInfo;

    private CertifiedKeyPair certKeyPair;
    private ASN1OctetString rspInfo;

    /**
     * Base constructor.
     *
     * @param certReqId the request ID for the response.
     * @param statusInfo the status info to associate with the response.
     */
    public CertificateResponseBuilder(ASN1Integer certReqId, PKIStatusInfo statusInfo)
    {
        this.certReqId = certReqId;
        this.statusInfo = statusInfo;
    }

    /**
     * Specify the certificate to assign to this response (in plaintext).
     *
     * @param certificate the X.509 PK certificate to include.
     * @return the current builder.
     */
    public CertificateResponseBuilder withCertificate(X509CertificateHolder certificate)
    {
        if (certKeyPair != null)
        {
            throw new IllegalStateException("certificate in response already set");
        }

        this.certKeyPair = new CertifiedKeyPair(
            new CertOrEncCert(new CMPCertificate(certificate.toASN1Structure())));

        return this;
    }

    /**
     * Specify the certificate to assign to this response (in plaintext).
     *
     * @param certificate the X.509 PK certificate to include.
     * @return the current builder.
     */
    public CertificateResponseBuilder withCertificate(CMPCertificate certificate)
    {
        if (certKeyPair != null)
        {
            throw new IllegalStateException("certificate in response already set");
        }

        this.certKeyPair = new CertifiedKeyPair(
            new CertOrEncCert(certificate));

        return this;
    }

    /**
     * Specify the encrypted certificate to assign to this response (in plaintext).
     *
     * @param encryptedCertificate an encrypted
     * @return the current builder.
     */
    public CertificateResponseBuilder withCertificate(CMSEnvelopedData encryptedCertificate)
    {
        if (certKeyPair != null)
        {
            throw new IllegalStateException("certificate in response already set");
        }

        this.certKeyPair = new CertifiedKeyPair(
            new CertOrEncCert(
                new EncryptedKey(EnvelopedData.getInstance(encryptedCertificate.toASN1Structure().getContent()))));

        return this;
    }

    /**
     * Specify the response info field on the response.
     *
     * @param responseInfo a response info string.
     * @return the current builder.
     */
    public CertificateResponseBuilder withResponseInfo(byte[] responseInfo)
    {
        if (rspInfo != null)
        {
            throw new IllegalStateException("response info already set");
        }

        this.rspInfo = new DEROctetString(responseInfo);

        return this;
    }

    public CertificateResponse build()
    {
        return new CertificateResponse(new CertResponse(certReqId, statusInfo, certKeyPair, rspInfo));
    }
}
