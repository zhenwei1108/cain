package com.github.wegoo.cain.asn1.est;

class Utils
{
    static AttrOrOID[] clone(AttrOrOID[] ids)
    {
        AttrOrOID[] tmp = new AttrOrOID[ids.length];

        System.arraycopy(ids, 0, tmp, 0, ids.length);

        return tmp;
    }
}
