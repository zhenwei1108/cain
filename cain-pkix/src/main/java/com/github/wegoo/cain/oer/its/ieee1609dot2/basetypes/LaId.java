package com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes;

import com.github.wegoo.cain.asn1.ASN1Object;
import com.github.wegoo.cain.asn1.ASN1OctetString;
import com.github.wegoo.cain.asn1.ASN1Primitive;
import com.github.wegoo.cain.asn1.DEROctetString;
import com.github.wegoo.cain.util.Arrays;


/**
 * LaId ::= OCTET STRING (SIZE(2))
 */
public class LaId
    extends ASN1Object
{
    private final byte[] laId;

    public LaId(byte[] laId)
    {
        this.laId = laId;
        assertLength();
    }

    private LaId(ASN1OctetString octetString)
    {
        this(octetString.getOctets());
    }

    public static LaId getInstance(Object o)
    {
        if (o instanceof LaId)
        {
            return (LaId)o;
        }
        if (o != null)
        {
            return new LaId(DEROctetString.getInstance(o));
        }
        return null;
    }


    private void assertLength()
    {
        if (laId.length != 2)
        {
            throw new IllegalArgumentException("laId must be 2 octets");
        }
    }

    public byte[] getLaId()
    {
        return Arrays.clone(laId);
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DEROctetString(laId);
    }
}
