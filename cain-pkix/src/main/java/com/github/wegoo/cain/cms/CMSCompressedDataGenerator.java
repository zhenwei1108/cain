package com.github.wegoo.cain.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import com.github.wegoo.cain.asn1.ASN1OctetString;
import com.github.wegoo.cain.asn1.BEROctetString;
import com.github.wegoo.cain.asn1.cms.CMSObjectIdentifiers;
import com.github.wegoo.cain.asn1.cms.CompressedData;
import com.github.wegoo.cain.asn1.cms.ContentInfo;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.operator.OutputCompressor;

/**
 * General class for generating a compressed CMS message.
 * <p>
 * A simple example of usage.
 * <p>
 * <pre>
 *      CMSCompressedDataGenerator  fact = new CMSCompressedDataGenerator();
 *
 *      CMSCompressedData           data = fact.generate(content, new ZlibCompressor());
 * </pre>
 */
public class CMSCompressedDataGenerator
{
    public static final String ZLIB = CMSObjectIdentifiers.zlibCompress.getId();

    /**
     * base constructor
     */
    public CMSCompressedDataGenerator()
    {
    }

    /**
     * generate an object that contains an CMS Compressed Data
     */
    public CMSCompressedData generate(
        CMSTypedData content,
        OutputCompressor compressor)
        throws CMSException
    {
        AlgorithmIdentifier     comAlgId;
        ASN1OctetString         comOcts;

        try
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            OutputStream zOut = compressor.getOutputStream(bOut);

            content.write(zOut);

            zOut.close();

            comAlgId = compressor.getAlgorithmIdentifier();
            comOcts = new BEROctetString(bOut.toByteArray());
        }
        catch (IOException e)
        {
            throw new CMSException("exception encoding data.", e);
        }

        ContentInfo     comContent = new ContentInfo(
                                    content.getContentType(), comOcts);

        ContentInfo     contentInfo = new ContentInfo(
                                    CMSObjectIdentifiers.compressedData,
                                    new CompressedData(comAlgId, comContent));

        return new CMSCompressedData(contentInfo);
    }
}
