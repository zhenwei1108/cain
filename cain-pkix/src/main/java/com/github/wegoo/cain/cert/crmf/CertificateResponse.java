package com.github.wegoo.cain.cert.crmf;

import java.util.Collection;

import com.github.wegoo.cain.asn1.cmp.CMPCertificate;
import com.github.wegoo.cain.asn1.cmp.CertResponse;
import com.github.wegoo.cain.asn1.cmp.CertifiedKeyPair;
import com.github.wegoo.cain.asn1.cms.ContentInfo;
import com.github.wegoo.cain.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.wegoo.cain.cms.CMSEnvelopedData;
import com.github.wegoo.cain.cms.CMSException;
import com.github.wegoo.cain.cms.Recipient;
import com.github.wegoo.cain.cms.RecipientInformation;
import com.github.wegoo.cain.cms.RecipientInformationStore;

/**
 * High level wrapper for the CertResponse CRMF structure.
 */
public class CertificateResponse
{
    private final CertResponse certResponse;

    public CertificateResponse(CertResponse certResponse)
    {

        this.certResponse = certResponse;
    }

    /**
     * Return true if the response contains an encrypted certificate.
     *
     * @return true if certificate in response encrypted, false otherwise.
     */
    public boolean hasEncryptedCertificate()
    {
        return certResponse.getCertifiedKeyPair().getCertOrEncCert().hasEncryptedCertificate();
    }

    /**
     * Return a CMSEnvelopedData representing the encrypted certificate contained in the response.
     *
     * @return a CMEEnvelopedData if an encrypted certificate is present.
     * @throws IllegalStateException if no encrypted certificate is present, or there is an issue with the enveloped data.
     */
    public CMSEnvelopedData getEncryptedCertificate()
        throws CMSException
    {
        if (!hasEncryptedCertificate())
        {
            throw new IllegalStateException("encrypted certificate asked for, none found");
        }

        CertifiedKeyPair receivedKeyPair = certResponse.getCertifiedKeyPair();

        CMSEnvelopedData envelopedData = new CMSEnvelopedData(
            new ContentInfo(PKCSObjectIdentifiers.envelopedData, receivedKeyPair.getCertOrEncCert().getEncryptedCert().getValue()));

        if (envelopedData.getRecipientInfos().size() != 1)
        {
            throw new IllegalStateException("data encrypted for more than one recipient");
        }

        return envelopedData;
    }

    /**
     * Return the CMPCertificate representing the plaintext certificate in the response.
     *
     * @return a CMPCertificate if a plaintext certificate is present.
     * @throws IllegalStateException if no plaintext certificate is present.
     */
    public CMPCertificate getCertificate(Recipient recipient)
        throws CMSException
    {
       CMSEnvelopedData encryptedCert = getEncryptedCertificate();

        RecipientInformationStore recipients = encryptedCert.getRecipientInfos();

        Collection c = recipients.getRecipients();

        RecipientInformation recInfo = (RecipientInformation)c.iterator().next();

        return CMPCertificate.getInstance(recInfo.getContent(recipient));
    }

    /**
     * Return the CMPCertificate representing the plaintext certificate in the response.
     *
     * @return a CMPCertificate if a plaintext certificate is present.
     * @throws IllegalStateException if no plaintext certificate is present.
     */
    public CMPCertificate getCertificate()
        throws CMSException
    {
        if (hasEncryptedCertificate())
        {
            throw new IllegalStateException("plaintext certificate asked for, none found");
        }

        return certResponse.getCertifiedKeyPair().getCertOrEncCert().getCertificate();
    }

    /**
     * Return this object's underlying ASN.1 structure.
     *
     * @return a CertResponse
     */
    public CertResponse toASN1Structure()
    {
        return certResponse;
    }
}
