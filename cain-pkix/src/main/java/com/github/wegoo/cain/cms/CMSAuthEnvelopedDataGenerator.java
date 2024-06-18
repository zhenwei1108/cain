package com.github.wegoo.cain.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import com.github.wegoo.cain.asn1.ASN1EncodableVector;
import com.github.wegoo.cain.asn1.ASN1Set;
import com.github.wegoo.cain.asn1.DEROctetString;
import com.github.wegoo.cain.asn1.DERSet;
import com.github.wegoo.cain.asn1.cms.AuthEnvelopedData;
import com.github.wegoo.cain.asn1.cms.CMSObjectIdentifiers;
import com.github.wegoo.cain.asn1.cms.ContentInfo;
import com.github.wegoo.cain.asn1.cms.EncryptedContentInfo;
import com.github.wegoo.cain.operator.OutputAEADEncryptor;

public class CMSAuthEnvelopedDataGenerator
    extends CMSAuthEnvelopedGenerator
{
    /**
     * base constructor
     */
    public CMSAuthEnvelopedDataGenerator()
    {
    }

    private CMSAuthEnvelopedData doGenerate(
        CMSTypedData content,
        OutputAEADEncryptor contentEncryptor)
        throws CMSException
    {
        ASN1EncodableVector recipientInfos = CMSUtils.getRecipentInfos(contentEncryptor.getKey(), recipientInfoGenerators);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1Set authenticatedAttrSet;
        try
        {
            OutputStream cOut = contentEncryptor.getOutputStream(bOut);

            content.write(cOut);

            authenticatedAttrSet = CMSUtils.processAuthAttrSet(authAttrsGenerator, contentEncryptor);

            cOut.close();
        }
        catch (IOException e)
        {
            throw new CMSException("unable to process authenticated content: " + e.getMessage(), e);
        }

        byte[] encryptedContent = bOut.toByteArray();
        byte[] mac = contentEncryptor.getMAC();

        EncryptedContentInfo eci = CMSUtils.getEncryptedContentInfo(content, contentEncryptor, encryptedContent);

        ASN1Set unprotectedAttrSet = CMSUtils.getAttrDLSet(unauthAttrsGenerator);

        ContentInfo contentInfo = new ContentInfo(
            CMSObjectIdentifiers.authEnvelopedData,
            new AuthEnvelopedData(originatorInfo, new DERSet(recipientInfos), eci, authenticatedAttrSet, new DEROctetString(mac), unprotectedAttrSet));

        return new CMSAuthEnvelopedData(contentInfo);
    }

    /**
     * generate an auth-enveloped object that contains an CMS Enveloped Data
     * object using the given provider.
     *
     * @param content the content to be encrypted
     * @param contentEncryptor the symmetric key based encryptor to encrypt the content with.
     */
    public CMSAuthEnvelopedData generate(
        CMSTypedData content,
        OutputAEADEncryptor contentEncryptor)
        throws CMSException
    {
        return doGenerate(content, contentEncryptor);
    }
}
