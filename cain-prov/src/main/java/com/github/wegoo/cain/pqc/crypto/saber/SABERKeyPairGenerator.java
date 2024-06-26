package com.github.wegoo.cain.pqc.crypto.saber;

import com.github.wegoo.cain.crypto.AsymmetricCipherKeyPair;
import com.github.wegoo.cain.crypto.AsymmetricCipherKeyPairGenerator;
import com.github.wegoo.cain.crypto.KeyGenerationParameters;

import java.security.SecureRandom;

public class SABERKeyPairGenerator
        implements AsymmetricCipherKeyPairGenerator
{
    private SABERKeyGenerationParameters saberParams;

    private int l;

    private SecureRandom random;

    private void initialize(
            KeyGenerationParameters param)
    {
        this.saberParams = (SABERKeyGenerationParameters) param;
        this.random = param.getRandom();

        this.l = this.saberParams.getParameters().getL();
    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        SABEREngine engine = saberParams.getParameters().getEngine();
        byte[] sk = new byte[engine.getPrivateKeySize()];
        byte[] pk = new byte[engine.getPublicKeySize()];
        engine.crypto_kem_keypair(pk, sk, random);

        SABERPublicKeyParameters pubKey = new SABERPublicKeyParameters(saberParams.getParameters(), pk);
        SABERPrivateKeyParameters privKey = new SABERPrivateKeyParameters(saberParams.getParameters(), sk);
        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }

    public void init(KeyGenerationParameters param)
    {
        this.initialize(param);
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return genKeyPair();
    }
}
