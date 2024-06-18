package com.github.wegoo.cain.pqc.jcajce.provider;

import com.github.wegoo.cain.asn1.bc.BCObjectIdentifiers;
import com.github.wegoo.cain.jcajce.provider.config.ConfigurableProvider;
import com.github.wegoo.cain.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.github.wegoo.cain.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.github.wegoo.cain.pqc.jcajce.provider.ntruprime.NTRULPRimeKeyFactorySpi;
import com.github.wegoo.cain.pqc.jcajce.provider.ntruprime.SNTRUPrimeKeyFactorySpi;

public class NTRUPrime
{
    private static final String PREFIX = "com.github.wegoo.cain.pqc.jcajce.provider" + ".ntruprime.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.NTRULPRIME", PREFIX + "NTRULPRimeKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.NTRULPRIME", PREFIX + "NTRULPRimeKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.NTRULPRIME", PREFIX + "NTRULPRimeKeyGeneratorSpi");

            AsymmetricKeyInfoConverter keyFact = new NTRULPRimeKeyFactorySpi();

            provider.addAlgorithm("Cipher.NTRULPRIME", PREFIX + "NTRULPRimeCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_ntrulprime, "NTRU");
            
            registerOid(provider, BCObjectIdentifiers.ntrulpr653, "NTRULPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.ntrulpr761, "NTRULPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.ntrulpr857, "NTRULPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.ntrulpr953, "NTRULPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.ntrulpr1013, "NTRULPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.ntrulpr1277, "NTRULPRIME", keyFact);
            
            provider.addAlgorithm("KeyFactory.SNTRUPRIME", PREFIX + "SNTRUPrimeKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.SNTRUPRIME", PREFIX + "SNTRUPrimeKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.SNTRUPRIME", PREFIX + "SNTRUPrimeKeyGeneratorSpi");

            keyFact = new SNTRUPrimeKeyFactorySpi();

            provider.addAlgorithm("Cipher.SNTRUPRIME", PREFIX + "SNTRUPrimeCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_sntruprime, "NTRU");

            registerOid(provider, BCObjectIdentifiers.sntrup653, "SNTRUPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.sntrup761, "SNTRUPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.sntrup857, "SNTRUPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.sntrup953, "SNTRUPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.sntrup1013, "SNTRUPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.sntrup1277, "SNTRUPRIME", keyFact);
        }
    }
}
