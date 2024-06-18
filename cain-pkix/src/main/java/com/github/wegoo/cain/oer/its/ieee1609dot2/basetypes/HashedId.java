package com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes;

import com.github.wegoo.cain.asn1.ASN1Object;
import com.github.wegoo.cain.asn1.ASN1Primitive;
import com.github.wegoo.cain.asn1.DEROctetString;
import com.github.wegoo.cain.util.Arrays;

public class HashedId
    extends ASN1Object

{
    private final byte[] id;

    protected HashedId(byte[] string)
    {
        this.id = Arrays.clone(string);
    }

    public byte[] getHashBytes()
    {
        return Arrays.clone(id);
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DEROctetString(id);
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }
        if (!super.equals(o))
        {
            return false;
        }

        HashedId hashedId = (HashedId)o;

        return java.util.Arrays.equals(id, hashedId.id);
    }

    @Override
    public int hashCode()
    {
        int result = super.hashCode();
        result = 31 * result + java.util.Arrays.hashCode(id);
        return result;
    }
}
