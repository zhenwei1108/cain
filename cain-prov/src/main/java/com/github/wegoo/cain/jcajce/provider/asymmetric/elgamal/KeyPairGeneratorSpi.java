package com.github.wegoo.cain.jcajce.provider.asymmetric.elgamal;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.DHParameterSpec;

import com.github.wegoo.cain.crypto.AsymmetricCipherKeyPair;
import com.github.wegoo.cain.crypto.CryptoServicesRegistrar;
import com.github.wegoo.cain.crypto.generators.ElGamalKeyPairGenerator;
import com.github.wegoo.cain.crypto.generators.ElGamalParametersGenerator;
import com.github.wegoo.cain.crypto.params.ElGamalKeyGenerationParameters;
import com.github.wegoo.cain.crypto.params.ElGamalParameters;
import com.github.wegoo.cain.crypto.params.ElGamalPrivateKeyParameters;
import com.github.wegoo.cain.crypto.params.ElGamalPublicKeyParameters;
import com.github.wegoo.cain.jce.provider.CainJCEProvider;
import com.github.wegoo.cain.jce.spec.ElGamalParameterSpec;

public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    ElGamalKeyGenerationParameters param;
    ElGamalKeyPairGenerator engine = new ElGamalKeyPairGenerator();
    int strength = 1024;
    int certainty = 20;
    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public KeyPairGeneratorSpi()
    {
        super("ElGamal");
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        this.strength = strength;
        this.random = random;
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof ElGamalParameterSpec) && !(params instanceof DHParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a DHParameterSpec or an ElGamalParameterSpec");
        }

        if (params instanceof ElGamalParameterSpec)
        {
            ElGamalParameterSpec elParams = (ElGamalParameterSpec)params;

            param = new ElGamalKeyGenerationParameters(random, new ElGamalParameters(elParams.getP(), elParams.getG()));
        }
        else
        {
            DHParameterSpec dhParams = (DHParameterSpec)params;

            param = new ElGamalKeyGenerationParameters(random, new ElGamalParameters(dhParams.getP(), dhParams.getG(), dhParams.getL()));
        }

        engine.init(param);
        initialised = true;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            DHParameterSpec dhParams = CainJCEProvider.CONFIGURATION.getDHDefaultParameters(strength);

            if (dhParams != null)
            {
                param = new ElGamalKeyGenerationParameters(random, new ElGamalParameters(dhParams.getP(), dhParams.getG(), dhParams.getL()));
            }
            else
            {
                ElGamalParametersGenerator pGen = new ElGamalParametersGenerator();

                pGen.init(strength, certainty, random);
                param = new ElGamalKeyGenerationParameters(random, pGen.generateParameters());
            }

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        ElGamalPublicKeyParameters pub = (ElGamalPublicKeyParameters)pair.getPublic();
        ElGamalPrivateKeyParameters priv = (ElGamalPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCElGamalPublicKey(pub),
            new BCElGamalPrivateKey(priv));
    }
}

