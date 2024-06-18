package com.github.wegoo.cain.oer.its.etsi102941;

import com.github.wegoo.cain.asn1.ASN1Sequence;
import com.github.wegoo.cain.oer.its.etsi103097.EtsiTs103097DataSigned;
import com.github.wegoo.cain.oer.its.ieee1609dot2.Ieee1609Dot2Content;

public class TlmLinkCertificateMessage
    extends EtsiTs103097DataSigned
{

    public TlmLinkCertificateMessage(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected TlmLinkCertificateMessage(ASN1Sequence src)
    {
        super(src);
    }

    public static TlmLinkCertificateMessage getInstance(Object o)
    {
        if (o instanceof TlmLinkCertificateMessage)
        {
            return (TlmLinkCertificateMessage)o;
        }
        if (o != null)
        {
            return new TlmLinkCertificateMessage(ASN1Sequence.getInstance(o));
        }
        return null;
    }


}
