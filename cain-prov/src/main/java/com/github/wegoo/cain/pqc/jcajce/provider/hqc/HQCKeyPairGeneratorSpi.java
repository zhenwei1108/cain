package com.github.wegoo.cain.pqc.jcajce.provider.hqc;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import com.github.wegoo.cain.crypto.AsymmetricCipherKeyPair;
import com.github.wegoo.cain.crypto.CryptoServicesRegistrar;
import com.github.wegoo.cain.pqc.crypto.hqc.HQCKeyGenerationParameters;
import com.github.wegoo.cain.pqc.crypto.hqc.HQCKeyPairGenerator;
import com.github.wegoo.cain.pqc.crypto.hqc.HQCParameters;
import com.github.wegoo.cain.pqc.crypto.hqc.HQCPrivateKeyParameters;
import com.github.wegoo.cain.pqc.crypto.hqc.HQCPublicKeyParameters;
import com.github.wegoo.cain.pqc.jcajce.provider.util.SpecUtil;
import com.github.wegoo.cain.pqc.jcajce.spec.HQCParameterSpec;
import com.github.wegoo.cain.util.Strings;

public class HQCKeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put("hqc-128", HQCParameters.hqc128);
        parameters.put("hqc-192", HQCParameters.hqc192);
        parameters.put("hqc-256", HQCParameters.hqc256);

        parameters.put(HQCParameterSpec.hqc128.getName(), HQCParameters.hqc128);
        parameters.put(HQCParameterSpec.hqc192.getName(), HQCParameters.hqc192);
        parameters.put(HQCParameterSpec.hqc256.getName(), HQCParameters.hqc256);
    }

    HQCKeyGenerationParameters param;
    HQCKeyPairGenerator engine = new HQCKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public HQCKeyPairGeneratorSpi()
    {
        super("HQC");
    }

    public void initialize(
            int strength,
            SecureRandom random)
    {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    public void initialize(
            AlgorithmParameterSpec params,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
    {
        String name = getNameFromParams(params);

        if (name != null)
        {
            param = new HQCKeyGenerationParameters(random, (HQCParameters)parameters.get(name));

            engine.init(param);
            initialised = true;
        }
        else
        {
            throw new InvalidAlgorithmParameterException("invalid ParameterSpec: " + params);
        }
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec)
    {
        if (paramSpec instanceof HQCParameterSpec)
        {
            HQCParameterSpec hqcParams = (HQCParameterSpec)paramSpec;
            return hqcParams.getName();
        }
        else
        {
            return Strings.toLowerCase(SpecUtil.getNameFrom(paramSpec));
        }
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            param = new HQCKeyGenerationParameters(random, HQCParameters.hqc128);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        HQCPublicKeyParameters pub = (HQCPublicKeyParameters)pair.getPublic();
        HQCPrivateKeyParameters priv = (HQCPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCHQCPublicKey(pub), new BCHQCPrivateKey(priv));
    }
}
