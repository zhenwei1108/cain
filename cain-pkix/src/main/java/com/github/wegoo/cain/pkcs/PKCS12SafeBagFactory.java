package com.github.wegoo.cain.pkcs;

import com.github.wegoo.cain.asn1.ASN1OctetString;
import com.github.wegoo.cain.asn1.ASN1Sequence;
import com.github.wegoo.cain.asn1.pkcs.ContentInfo;
import com.github.wegoo.cain.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.wegoo.cain.asn1.pkcs.SafeBag;
import com.github.wegoo.cain.cms.CMSEncryptedData;
import com.github.wegoo.cain.cms.CMSException;
import com.github.wegoo.cain.operator.InputDecryptorProvider;

public class PKCS12SafeBagFactory
{
    private ASN1Sequence safeBagSeq;

    public PKCS12SafeBagFactory(ContentInfo info)
    {
        if (info.getContentType().equals(PKCSObjectIdentifiers.encryptedData))
        {
            throw new IllegalArgumentException("encryptedData requires constructor with decryptor.");
        }

        this.safeBagSeq = ASN1Sequence.getInstance(ASN1OctetString.getInstance(info.getContent()).getOctets());
    }

    public PKCS12SafeBagFactory(ContentInfo info, InputDecryptorProvider inputDecryptorProvider)
        throws PKCSException
    {
        if (info.getContentType().equals(PKCSObjectIdentifiers.encryptedData))
        {
            CMSEncryptedData encData = new CMSEncryptedData(com.github.wegoo.cain.asn1.cms.ContentInfo.getInstance(info));

            try
            {
                this.safeBagSeq = ASN1Sequence.getInstance(encData.getContent(inputDecryptorProvider));
            }
            catch (CMSException e)
            {
                throw new PKCSException("unable to extract data: " + e.getMessage(), e);
            }
            return;
        }

        throw new IllegalArgumentException("encryptedData requires constructor with decryptor.");
    }

    public PKCS12SafeBag[] getSafeBags()
    {
        PKCS12SafeBag[] safeBags = new PKCS12SafeBag[safeBagSeq.size()];

        for (int i = 0; i != safeBagSeq.size(); i++)
        {
            safeBags[i] = new PKCS12SafeBag(SafeBag.getInstance(safeBagSeq.getObjectAt(i)));
        }

        return safeBags;
    }
}
