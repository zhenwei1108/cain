package com.github.wegoo.cain.jcajce.provider.digest;

import com.github.wegoo.cain.crypto.CipherKeyGenerator;
import com.github.wegoo.cain.crypto.digests.RIPEMD320Digest;
import com.github.wegoo.cain.crypto.macs.HMac;
import com.github.wegoo.cain.jcajce.provider.config.ConfigurableProvider;
import com.github.wegoo.cain.jcajce.provider.symmetric.util.BaseKeyGenerator;
import com.github.wegoo.cain.jcajce.provider.symmetric.util.BaseMac;

public class RIPEMD320
{
    private RIPEMD320()
    {

    }

    static public class Digest
        extends BCMessageDigest
        implements Cloneable
    {
        public Digest()
        {
            super(new RIPEMD320Digest());
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            Digest d = (Digest)super.clone();
            d.digest = new RIPEMD320Digest((RIPEMD320Digest)digest);

            return d;
        }
    }

    /**
     * RIPEMD320 HMac
     */
    public static class HashMac
        extends BaseMac
    {
        public HashMac()
        {
            super(new HMac(new RIPEMD320Digest()));
        }
    }

    public static class KeyGenerator
        extends BaseKeyGenerator
    {
        public KeyGenerator()
        {
            super("HMACRIPEMD320", 320, new CipherKeyGenerator());
        }
    }

    public static class Mappings
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = RIPEMD320.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("MessageDigest.RIPEMD320", PREFIX + "$Digest");

            addHMACAlgorithm(provider, "RIPEMD320", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
        }
    }
}
