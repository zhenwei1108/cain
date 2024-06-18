package com.github.wegoo.cain.oer.its.etsi102941;

import com.github.wegoo.cain.asn1.ASN1Sequence;
import com.github.wegoo.cain.oer.its.etsi103097.EtsiTs103097DataEncryptedUnicast;
import com.github.wegoo.cain.oer.its.ieee1609dot2.Ieee1609Dot2Content;

public class AuthorizationResponseMessage
    extends EtsiTs103097DataEncryptedUnicast
{

    public AuthorizationResponseMessage(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected AuthorizationResponseMessage(ASN1Sequence src)
    {
        super(src);
    }

    public static AuthorizationResponseMessage getInstance(Object o)
    {
        if (o instanceof AuthorizationResponseMessage)
        {
            return (AuthorizationResponseMessage)o;
        }
        if (o != null)
        {
            return new AuthorizationResponseMessage(ASN1Sequence.getInstance(o));
        }
        return null;
    }


}
