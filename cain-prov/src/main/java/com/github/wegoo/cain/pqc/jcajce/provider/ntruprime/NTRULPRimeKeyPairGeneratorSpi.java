package com.github.wegoo.cain.pqc.jcajce.provider.ntruprime;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import com.github.wegoo.cain.crypto.AsymmetricCipherKeyPair;
import com.github.wegoo.cain.crypto.CryptoServicesRegistrar;
import com.github.wegoo.cain.pqc.crypto.ntruprime.NTRULPRimeKeyGenerationParameters;
import com.github.wegoo.cain.pqc.crypto.ntruprime.NTRULPRimeKeyPairGenerator;
import com.github.wegoo.cain.pqc.crypto.ntruprime.NTRULPRimeParameters;
import com.github.wegoo.cain.pqc.crypto.ntruprime.NTRULPRimePrivateKeyParameters;
import com.github.wegoo.cain.pqc.crypto.ntruprime.NTRULPRimePublicKeyParameters;
import com.github.wegoo.cain.pqc.jcajce.provider.util.SpecUtil;
import com.github.wegoo.cain.pqc.jcajce.spec.NTRULPRimeParameterSpec;
import com.github.wegoo.cain.util.Strings;

public class NTRULPRimeKeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(NTRULPRimeParameterSpec.ntrulpr653.getName(), NTRULPRimeParameters.ntrulpr653);
        parameters.put(NTRULPRimeParameterSpec.ntrulpr761.getName(), NTRULPRimeParameters.ntrulpr761);
        parameters.put(NTRULPRimeParameterSpec.ntrulpr857.getName(), NTRULPRimeParameters.ntrulpr857);
        parameters.put(NTRULPRimeParameterSpec.ntrulpr953.getName(), NTRULPRimeParameters.ntrulpr953);
        parameters.put(NTRULPRimeParameterSpec.ntrulpr1013.getName(), NTRULPRimeParameters.ntrulpr1013);
        parameters.put(NTRULPRimeParameterSpec.ntrulpr1277.getName(), NTRULPRimeParameters.ntrulpr1277);
    }

    NTRULPRimeKeyGenerationParameters param;
    NTRULPRimeKeyPairGenerator engine = new NTRULPRimeKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public NTRULPRimeKeyPairGeneratorSpi()
    {
        super("NTRULPRime");
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
            param = new NTRULPRimeKeyGenerationParameters(random, (NTRULPRimeParameters)parameters.get(name));

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
        if (paramSpec instanceof NTRULPRimeParameterSpec)
        {
            NTRULPRimeParameterSpec frodoParams = (NTRULPRimeParameterSpec)paramSpec;
            return frodoParams.getName();
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
            param = new NTRULPRimeKeyGenerationParameters(random, NTRULPRimeParameters.ntrulpr953);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        NTRULPRimePublicKeyParameters pub = (NTRULPRimePublicKeyParameters)pair.getPublic();
        NTRULPRimePrivateKeyParameters priv = (NTRULPRimePrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCNTRULPRimePublicKey(pub), new BCNTRULPRimePrivateKey(priv));
    }
}
