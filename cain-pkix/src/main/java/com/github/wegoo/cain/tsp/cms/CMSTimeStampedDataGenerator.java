package com.github.wegoo.cain.tsp.cms;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import com.github.wegoo.cain.asn1.ASN1IA5String;
import com.github.wegoo.cain.asn1.ASN1OctetString;
import com.github.wegoo.cain.asn1.BEROctetString;
import com.github.wegoo.cain.asn1.DERIA5String;
import com.github.wegoo.cain.asn1.cms.CMSObjectIdentifiers;
import com.github.wegoo.cain.asn1.cms.ContentInfo;
import com.github.wegoo.cain.asn1.cms.Evidence;
import com.github.wegoo.cain.asn1.cms.TimeStampAndCRL;
import com.github.wegoo.cain.asn1.cms.TimeStampTokenEvidence;
import com.github.wegoo.cain.asn1.cms.TimeStampedData;
import com.github.wegoo.cain.cms.CMSException;
import com.github.wegoo.cain.tsp.TimeStampToken;
import com.github.wegoo.cain.util.io.Streams;

public class CMSTimeStampedDataGenerator
    extends CMSTimeStampedGenerator
{
    public CMSTimeStampedData generate(TimeStampToken timeStamp) throws CMSException
    {
        return generate(timeStamp, (InputStream)null);
    }

    public CMSTimeStampedData generate(TimeStampToken timeStamp, byte[] content) throws CMSException
    {
        return generate(timeStamp, new ByteArrayInputStream(content));
    }

    public CMSTimeStampedData generate(TimeStampToken timeStamp, InputStream content)
        throws CMSException
    {
        ByteArrayOutputStream contentOut = new ByteArrayOutputStream();

        if (content != null)
        {
            try
            {
                Streams.pipeAll(content, contentOut);
            }
            catch (IOException e)
            {
                throw new CMSException("exception encapsulating content: " + e.getMessage(), e);
            }
        }

        ASN1OctetString encContent = null;

        if (contentOut.size() != 0)
        {
            encContent = new BEROctetString(contentOut.toByteArray());
        }

        TimeStampAndCRL stamp = new TimeStampAndCRL(timeStamp.toCMSSignedData().toASN1Structure());

        ASN1IA5String asn1DataUri = null;

        if (dataUri != null)
        {
            asn1DataUri = new DERIA5String(dataUri.toString());
        }
        
        return new CMSTimeStampedData(new ContentInfo(CMSObjectIdentifiers.timestampedData, new TimeStampedData(asn1DataUri, metaData, encContent, new Evidence(new TimeStampTokenEvidence(stamp)))));
    }
}

