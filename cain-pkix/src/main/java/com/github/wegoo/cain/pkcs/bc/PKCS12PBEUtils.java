package com.github.wegoo.cain.pkcs.bc;

import java.io.OutputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.github.wegoo.cain.asn1.ASN1ObjectIdentifier;
import com.github.wegoo.cain.asn1.pkcs.PKCS12PBEParams;
import com.github.wegoo.cain.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.crypto.BlockCipher;
import com.github.wegoo.cain.crypto.CipherParameters;
import com.github.wegoo.cain.crypto.ExtendedDigest;
import com.github.wegoo.cain.crypto.engines.DESedeEngine;
import com.github.wegoo.cain.crypto.engines.RC2Engine;
import com.github.wegoo.cain.crypto.generators.PKCS12ParametersGenerator;
import com.github.wegoo.cain.crypto.io.MacOutputStream;
import com.github.wegoo.cain.crypto.macs.HMac;
import com.github.wegoo.cain.crypto.modes.CBCBlockCipher;
import com.github.wegoo.cain.crypto.paddings.PKCS7Padding;
import com.github.wegoo.cain.crypto.paddings.PaddedBufferedBlockCipher;
import com.github.wegoo.cain.crypto.params.DESedeParameters;
import com.github.wegoo.cain.crypto.params.KeyParameter;
import com.github.wegoo.cain.crypto.params.ParametersWithIV;
import com.github.wegoo.cain.operator.GenericKey;
import com.github.wegoo.cain.operator.MacCalculator;
import com.github.wegoo.cain.util.Integers;

class PKCS12PBEUtils
{
    private static Map keySizes = new HashMap();
    private static Set noIvAlgs = new HashSet();
    private static Set desAlgs = new HashSet();

    static
    {
        keySizes.put(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC4, Integers.valueOf(128));
        keySizes.put(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC4, Integers.valueOf(40));
        keySizes.put(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, Integers.valueOf(192));
        keySizes.put(PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC, Integers.valueOf(128));
        keySizes.put(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC, Integers.valueOf(128));
        keySizes.put(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC, Integers.valueOf(40));

        noIvAlgs.add(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC4);
        noIvAlgs.add(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC4);

        desAlgs.add(PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC);
        desAlgs.add(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC);
    }

    static int getKeySize(ASN1ObjectIdentifier algorithm)
    {
        return ((Integer)keySizes.get(algorithm)).intValue();
    }

    static boolean hasNoIv(ASN1ObjectIdentifier algorithm)
    {
        return noIvAlgs.contains(algorithm);
    }

    static boolean isDesAlg(ASN1ObjectIdentifier algorithm)
    {
        return desAlgs.contains(algorithm);
    }

    static PaddedBufferedBlockCipher getEngine(ASN1ObjectIdentifier algorithm)
    {
        BlockCipher engine;

        if (algorithm.equals(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC)
            || algorithm.equals(PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC))
        {
            engine = new DESedeEngine();
        }
        else if (algorithm.equals(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC)
            || algorithm.equals(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC))
        {
            engine = new RC2Engine();
        }
        else
        {
            throw new IllegalStateException("unknown algorithm");
        }

        return new PaddedBufferedBlockCipher(new CBCBlockCipher(engine), new PKCS7Padding());
    }

    static MacCalculator createMacCalculator(final ASN1ObjectIdentifier digestAlgorithm, ExtendedDigest digest, final PKCS12PBEParams pbeParams, final char[] password)
    {
        PKCS12ParametersGenerator pGen = new PKCS12ParametersGenerator(digest);

        pGen.init(PKCS12ParametersGenerator.PKCS12PasswordToBytes(password), pbeParams.getIV(), pbeParams.getIterations().intValue());

        final KeyParameter keyParam = (KeyParameter)pGen.generateDerivedMacParameters(digest.getDigestSize() * 8);

        final HMac hMac = new HMac(digest);

        hMac.init(keyParam);

        return new MacCalculator()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return new AlgorithmIdentifier(digestAlgorithm, pbeParams);
            }

            public OutputStream getOutputStream()
            {
                return new MacOutputStream(hMac);
            }

            public byte[] getMac()
            {
                byte[] res = new byte[hMac.getMacSize()];

                hMac.doFinal(res, 0);

                return res;
            }

            public GenericKey getKey()
            {
                return new GenericKey(getAlgorithmIdentifier(), PKCS12ParametersGenerator.PKCS12PasswordToBytes(password));
            }
        };
    }

    static CipherParameters createCipherParameters(ASN1ObjectIdentifier algorithm, ExtendedDigest digest, int blockSize, PKCS12PBEParams pbeParams, char[] password)
    {
        PKCS12ParametersGenerator pGen = new PKCS12ParametersGenerator(digest);

        pGen.init(PKCS12ParametersGenerator.PKCS12PasswordToBytes(password), pbeParams.getIV(), pbeParams.getIterations().intValue());

        CipherParameters params;

        if (PKCS12PBEUtils.hasNoIv(algorithm))
        {
            params = pGen.generateDerivedParameters(PKCS12PBEUtils.getKeySize(algorithm));
        }
        else
        {
            params = pGen.generateDerivedParameters(PKCS12PBEUtils.getKeySize(algorithm), blockSize * 8);

            if (PKCS12PBEUtils.isDesAlg(algorithm))
            {
                DESedeParameters.setOddParity(((KeyParameter)((ParametersWithIV)params).getParameters()).getKey());
            }
        }
        return params;
    }
}
