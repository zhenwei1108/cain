package com.github.wegoo.cain.oer.its.ieee1609dot2;


import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;

import com.github.wegoo.cain.asn1.ASN1Encodable;
import com.github.wegoo.cain.asn1.ASN1Object;
import com.github.wegoo.cain.asn1.ASN1OctetString;
import com.github.wegoo.cain.asn1.ASN1Primitive;
import com.github.wegoo.cain.asn1.DEROctetString;
import com.github.wegoo.cain.oer.Element;
import com.github.wegoo.cain.oer.OERInputStream;
import com.github.wegoo.cain.util.Arrays;

public class Opaque
    extends ASN1Object
{
    private final byte[] content;

    public Opaque(byte[] content)
    {
        this.content = Arrays.clone(content);
    }

    private Opaque(ASN1OctetString value)
    {
        this(value.getOctets());
    }

    public static Opaque getInstance(Object src)
    {
        if (src instanceof Opaque)
        {
            return (Opaque)src;
        }
        if (src != null)
        {
            return new Opaque(ASN1OctetString.getInstance(src));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DEROctetString(content);
    }

    public byte[] getContent()
    {
        return content;
    }

    public InputStream getInputStream()
    {
        return new ByteArrayInputStream(content);
    }

    public static <T> T getValue(final Class<T> type, final Element definition, final Opaque src)
    {
        return AccessController.doPrivileged(new PrivilegedAction<T>()
        {
            public T run()
            {
                try
                {
                    ASN1Encodable value = OERInputStream.parse(src.content, definition);
                    Method m = type.getMethod("getInstance", Object.class);
                    return type.cast(m.invoke(null, value));
                }
                catch (Exception ex)
                {
                    throw new IllegalStateException("could not invoke getInstance on type " + ex.getMessage(), ex);
                }
            }
        });
    }

}
