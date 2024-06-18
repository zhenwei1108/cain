package com.github.wegoo.cain.jcajce.provider.digest;

import com.github.wegoo.cain.crypto.digests.Blake3Digest;
import com.github.wegoo.cain.internal.asn1.misc.MiscObjectIdentifiers;
import com.github.wegoo.cain.jcajce.provider.config.ConfigurableProvider;

public class Blake3
{
    private Blake3()
    {

    }

    static public class Blake3_256
        extends BCMessageDigest
        implements Cloneable
    {
        public Blake3_256()
        {
            super(new Blake3Digest(256));
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            Blake3_256 d = (Blake3_256)super.clone();
            d.digest = new Blake3Digest((Blake3Digest)digest);

            return d;
        }
    }

    public static class Mappings
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = Blake3.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("MessageDigest.BLAKE3-256", PREFIX + "$Blake3_256");
            provider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers.blake3_256, "BLAKE3-256");
        }
    }
}
