package com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes;

import com.github.wegoo.cain.asn1.ASN1Object;
import com.github.wegoo.cain.asn1.ASN1Primitive;
import com.github.wegoo.cain.asn1.ASN1String;
import com.github.wegoo.cain.asn1.ASN1UTF8String;
import com.github.wegoo.cain.asn1.DERUTF8String;

/**
 * Hostname ::= UTF8String (SIZE(0..255))
 */
public class Hostname
    extends ASN1Object
{
    private final String hostName;

    public Hostname(String hostName)
    {
        this.hostName = hostName;
    }

    private Hostname(ASN1String string)
    {
        this.hostName = string.getString();
    }

    public static Hostname getInstance(Object src)
    {
        if (src instanceof Hostname)
        {
            return (Hostname)src;
        }

        if (src != null)
        {
            return new Hostname(ASN1UTF8String.getInstance(src));
        }

        return null;

    }

    public String getHostName()
    {
        return hostName;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERUTF8String(hostName);
    }
}
