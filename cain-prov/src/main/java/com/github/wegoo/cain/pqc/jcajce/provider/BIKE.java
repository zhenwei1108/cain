package com.github.wegoo.cain.pqc.jcajce.provider;

import com.github.wegoo.cain.asn1.bc.BCObjectIdentifiers;
import com.github.wegoo.cain.jcajce.provider.config.ConfigurableProvider;
import com.github.wegoo.cain.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.github.wegoo.cain.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.github.wegoo.cain.pqc.jcajce.provider.bike.BIKEKeyFactorySpi;

public class BIKE
{
    private static final String PREFIX = "com.github.wegoo.cain.pqc.jcajce.provider" + ".bike.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.BIKE", PREFIX + "BIKEKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.BIKE", PREFIX + "BIKEKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.BIKE", PREFIX + "BIKEKeyGeneratorSpi");

            AsymmetricKeyInfoConverter keyFact = new BIKEKeyFactorySpi();

            provider.addAlgorithm("Cipher.BIKE", PREFIX + "BIKECipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_bike, "BIKE");

            addCipherAlgorithm(provider, "BIKE128", PREFIX + "BIKECipherSpi$BIKE128", BCObjectIdentifiers.bike128);
            addCipherAlgorithm(provider, "BIKE192", PREFIX + "BIKECipherSpi$BIKE192", BCObjectIdentifiers.bike192);
            addCipherAlgorithm(provider, "BIKE256", PREFIX + "BIKECipherSpi$BIKE256", BCObjectIdentifiers.bike256);

            registerOid(provider, BCObjectIdentifiers.pqc_kem_bike, "BIKE", keyFact);
        }
    }
}
