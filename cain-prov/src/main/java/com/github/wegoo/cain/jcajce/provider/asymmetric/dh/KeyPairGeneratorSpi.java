package com.github.wegoo.cain.jcajce.provider.asymmetric.dh;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Hashtable;

import javax.crypto.spec.DHParameterSpec;

import com.github.wegoo.cain.crypto.AsymmetricCipherKeyPair;
import com.github.wegoo.cain.crypto.CryptoServicesRegistrar;
import com.github.wegoo.cain.crypto.generators.DHBasicKeyPairGenerator;
import com.github.wegoo.cain.crypto.generators.DHParametersGenerator;
import com.github.wegoo.cain.crypto.params.DHKeyGenerationParameters;
import com.github.wegoo.cain.crypto.params.DHParameters;
import com.github.wegoo.cain.crypto.params.DHPrivateKeyParameters;
import com.github.wegoo.cain.crypto.params.DHPublicKeyParameters;
import com.github.wegoo.cain.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;
import com.github.wegoo.cain.jcajce.spec.DHDomainParameterSpec;
import com.github.wegoo.cain.jce.provider.CainJCEProvider;
import com.github.wegoo.cain.util.Integers;

public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Hashtable params = new Hashtable();
    private static Object    lock = new Object();

    DHKeyGenerationParameters param;
    DHBasicKeyPairGenerator engine = new DHBasicKeyPairGenerator();
    int strength = 2048;
    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public KeyPairGeneratorSpi()
    {
        super("DH");
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        this.strength = strength;
        this.random = random;
        this.initialised = false;
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof DHParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a DHParameterSpec");
        }
        DHParameterSpec dhParams = (DHParameterSpec)params;

        try
        {
            param = convertParams(random, dhParams);
        }
        catch (IllegalArgumentException e)
        {
            throw new InvalidAlgorithmParameterException(e.getMessage(), e);
        }
        
        engine.init(param);
        initialised = true;
    }

    private DHKeyGenerationParameters convertParams(SecureRandom random, DHParameterSpec dhParams)
    {
        if (dhParams instanceof DHDomainParameterSpec)
        {
            return new DHKeyGenerationParameters(random, ((DHDomainParameterSpec)dhParams).getDomainParameters());
        }
        return new DHKeyGenerationParameters(random, new DHParameters(dhParams.getP(), dhParams.getG(), null, dhParams.getL()));
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            Integer paramStrength = Integers.valueOf(strength);

            if (params.containsKey(paramStrength))
            {
                param = (DHKeyGenerationParameters)params.get(paramStrength);
            }
            else
            {
                DHParameterSpec dhParams = CainJCEProvider.CONFIGURATION.getDHDefaultParameters(strength);

                if (dhParams != null)
                {   
                    param = convertParams(random, dhParams);
                }
                else
                {
                    synchronized (lock)
                    {
                        // we do the check again in case we were blocked by a generator for
                        // our key size.
                        if (params.containsKey(paramStrength))
                        {
                            param = (DHKeyGenerationParameters)params.get(paramStrength);
                        }
                        else
                        {

                            DHParametersGenerator pGen = new DHParametersGenerator();

                            pGen.init(strength, PrimeCertaintyCalculator.getDefaultCertainty(strength), random);

                            param = new DHKeyGenerationParameters(random, pGen.generateParameters());

                            params.put(paramStrength, param);
                        }
                    }
                }
            }

            engine.init(param);

            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        DHPublicKeyParameters pub = (DHPublicKeyParameters)pair.getPublic();
        DHPrivateKeyParameters priv = (DHPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCDHPublicKey(pub), new BCDHPrivateKey(priv));
    }
}
