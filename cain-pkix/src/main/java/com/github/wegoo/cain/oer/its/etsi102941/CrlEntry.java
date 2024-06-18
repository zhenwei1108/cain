package com.github.wegoo.cain.oer.its.etsi102941;

import com.github.wegoo.cain.asn1.ASN1OctetString;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.HashedId;

public class CrlEntry
    extends HashedId
{
    public CrlEntry(byte[] string)
    {
        super(string);
        if (string.length != 8)
        {
            throw new IllegalArgumentException("expected 8 bytes");
        }
    }

    private CrlEntry(ASN1OctetString instance)
    {
        super(instance.getOctets());
    }

    public static CrlEntry getInstance(Object o)
    {
        if (o instanceof CrlEntry)
        {
            return (CrlEntry)o;
        }
        if (o != null)
        {
            return new CrlEntry(ASN1OctetString.getInstance(o));
        }

        return null;
    }


}
