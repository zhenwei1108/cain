package com.github.wegoo.cain.asn1.x500.style;

import com.github.wegoo.cain.asn1.x500.RDN;
import com.github.wegoo.cain.asn1.x500.X500Name;
import com.github.wegoo.cain.asn1.x500.X500NameStyle;

/**
 * Variation of BCStyle that insists on strict ordering for equality
 * and hashCode comparisons
 */
public class BCStrictStyle
    extends BCStyle
{
    public static final X500NameStyle INSTANCE = new BCStrictStyle();

    public boolean areEqual(X500Name name1, X500Name name2)
    {
        if (name1.size() != name2.size())
        {
            return false;
        }

        RDN[] rdns1 = name1.getRDNs();
        RDN[] rdns2 = name2.getRDNs();

        for (int i = 0; i != rdns1.length; i++)
        {
            if (!rdnAreEqual(rdns1[i], rdns2[i]))
            {
                return false;
            }
        }

        return true;
    }
}
