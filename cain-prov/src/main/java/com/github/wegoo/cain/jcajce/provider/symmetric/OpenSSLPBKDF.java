package com.github.wegoo.cain.jcajce.provider.symmetric;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.github.wegoo.cain.crypto.generators.OpenSSLPBEParametersGenerator;
import com.github.wegoo.cain.crypto.params.KeyParameter;
import com.github.wegoo.cain.jcajce.provider.config.ConfigurableProvider;
import com.github.wegoo.cain.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
import com.github.wegoo.cain.jcajce.provider.util.AlgorithmProvider;
import com.github.wegoo.cain.util.Strings;

public final class OpenSSLPBKDF
{
    private OpenSSLPBKDF()
    {
    }

    public static class PBKDF
        extends BaseSecretKeyFactory
    {
        public PBKDF()
        {
            super("PBKDF-OpenSSL", null);
        }

        protected SecretKey engineGenerateSecret(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof PBEKeySpec)
            {
                PBEKeySpec pbeSpec = (PBEKeySpec)keySpec;

                if (pbeSpec.getSalt() == null)
                {
                    throw new InvalidKeySpecException("missing required salt");
                }

                if (pbeSpec.getIterationCount() <= 0)
                {
                    throw new InvalidKeySpecException("positive iteration count required: "
                        + pbeSpec.getIterationCount());
                }

                if (pbeSpec.getKeyLength() <= 0)
                {
                    throw new InvalidKeySpecException("positive key length required: "
                        + pbeSpec.getKeyLength());
                }

                if (pbeSpec.getPassword().length == 0)
                {
                    throw new IllegalArgumentException("password empty");
                }

                OpenSSLPBEParametersGenerator pGen = new OpenSSLPBEParametersGenerator();

                pGen.init(Strings.toUTF8ByteArray(pbeSpec.getPassword()), pbeSpec.getSalt());

                return new SecretKeySpec(((KeyParameter)pGen.generateDerivedParameters(pbeSpec.getKeyLength())).getKey(), "OpenSSLPBKDF");
            }

            throw new InvalidKeySpecException("Invalid KeySpec");
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = OpenSSLPBKDF.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("SecretKeyFactory.PBKDF-OPENSSL", PREFIX + "$PBKDF");
        }
    }
}
