package com.github.wegoo.cain.jcajce.provider.symmetric;

import com.github.wegoo.cain.crypto.BufferedBlockCipher;
import com.github.wegoo.cain.crypto.CipherKeyGenerator;
import com.github.wegoo.cain.crypto.engines.GOST3412_2015Engine;
import com.github.wegoo.cain.crypto.macs.CMac;
import com.github.wegoo.cain.crypto.modes.G3413CBCBlockCipher;
import com.github.wegoo.cain.crypto.modes.G3413CFBBlockCipher;
import com.github.wegoo.cain.crypto.modes.G3413CTRBlockCipher;
import com.github.wegoo.cain.crypto.modes.G3413OFBBlockCipher;
import com.github.wegoo.cain.jcajce.provider.config.ConfigurableProvider;
import com.github.wegoo.cain.jcajce.provider.symmetric.util.BaseBlockCipher;
import com.github.wegoo.cain.jcajce.provider.symmetric.util.BaseKeyGenerator;
import com.github.wegoo.cain.jcajce.provider.symmetric.util.BaseMac;
import com.github.wegoo.cain.jcajce.provider.util.AlgorithmProvider;


public class GOST3412_2015
{
    public static class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new GOST3412_2015Engine());
        }
    }

    public static class CBC
        extends BaseBlockCipher
    {
        public CBC()
        {
            super(new G3413CBCBlockCipher(new GOST3412_2015Engine()), false, 128);
        }
    }

    public static class GCFB
        extends BaseBlockCipher
    {
        public GCFB()
        {
            super(new BufferedBlockCipher(new G3413CFBBlockCipher(new GOST3412_2015Engine())), false, 128);
        }
    }

    public static class GCFB8
        extends BaseBlockCipher
    {
        public GCFB8()
        {
            super(new BufferedBlockCipher(new G3413CFBBlockCipher(new GOST3412_2015Engine(), 8)), false, 128);
        }
    }

    public static class OFB
        extends BaseBlockCipher
    {
        public OFB()
        {
            super(new BufferedBlockCipher(new G3413OFBBlockCipher(new GOST3412_2015Engine())), false, 128);
        }

    }

    public static class CTR
        extends BaseBlockCipher
    {
        public CTR()
        {
            super(new BufferedBlockCipher(new G3413CTRBlockCipher(new GOST3412_2015Engine())), true,64);
        }

    }

    /**
     * GOST3412 2015 CMAC( OMAC1)
     */
    public static class Mac
        extends BaseMac
    {
        public Mac()
        {
            super(new CMac(new GOST3412_2015Engine()));
        }
    }


    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            this(256);
        }

        public KeyGen(int keySize)
        {
            super("GOST3412-2015", keySize, new CipherKeyGenerator());
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = GOST3412_2015.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Cipher.GOST3412-2015", PREFIX + "$ECB");
            provider.addAlgorithm("Cipher.GOST3412-2015/CFB", PREFIX + "$GCFB");
            provider.addAlgorithm("Cipher.GOST3412-2015/CFB8", PREFIX + "$GCFB8");
            provider.addAlgorithm("Cipher.GOST3412-2015/OFB", PREFIX + "$OFB");
            provider.addAlgorithm("Cipher.GOST3412-2015/CBC", PREFIX + "$CBC");
            provider.addAlgorithm("Cipher.GOST3412-2015/CTR", PREFIX + "$CTR");

            provider.addAlgorithm("KeyGenerator.GOST3412-2015", PREFIX + "$KeyGen");;

            provider.addAlgorithm("Mac.GOST3412MAC", PREFIX + "$Mac");
            provider.addAlgorithm("Alg.Alias.Mac.GOST3412-2015", "GOST3412MAC");
        }
    }


}
