package com.github.wegoo.cain.pqc.jcajce.provider.newhope;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.ShortBufferException;

import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;
import com.github.wegoo.cain.jcajce.provider.asymmetric.util.BaseAgreementSpi;
import com.github.wegoo.cain.pqc.crypto.ExchangePair;
import com.github.wegoo.cain.pqc.crypto.newhope.NHAgreement;
import com.github.wegoo.cain.pqc.crypto.newhope.NHExchangePairGenerator;
import com.github.wegoo.cain.pqc.crypto.newhope.NHPublicKeyParameters;
import com.github.wegoo.cain.util.Arrays;

public class KeyAgreementSpi
    extends BaseAgreementSpi
{
    private NHAgreement agreement;
    private BCNHPublicKey otherPartyKey;
    private NHExchangePairGenerator exchangePairGenerator;

    private byte[] shared;

    public KeyAgreementSpi()
    {
        super("NH", null);
    }

    protected void engineInit(Key key, SecureRandom secureRandom)
        throws InvalidKeyException
    {
        if (key != null)
        {
            agreement = new NHAgreement();

            agreement.init(((BCNHPrivateKey)key).getKeyParams());
        }
        else
        {
            exchangePairGenerator = new NHExchangePairGenerator(secureRandom);
        }
    }

    protected void doInitFromKey(Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        throw new InvalidAlgorithmParameterException("NewHope does not require parameters");
    }

    protected Key engineDoPhase(Key key, boolean lastPhase)
        throws InvalidKeyException, IllegalStateException
    {
        if (!lastPhase)
        {
            throw new IllegalStateException("NewHope can only be between two parties.");
        }

        otherPartyKey = (BCNHPublicKey)key;

        if (exchangePairGenerator != null)
        {
            ExchangePair exchPair = exchangePairGenerator.generateExchange((AsymmetricKeyParameter)otherPartyKey.getKeyParams());

            shared = exchPair.getSharedValue();

            return new BCNHPublicKey((NHPublicKeyParameters)exchPair.getPublicKey());
        }
        else
        {
            shared = agreement.calculateAgreement(otherPartyKey.getKeyParams());

            return null;
        }
    }

    protected byte[] engineGenerateSecret()
        throws IllegalStateException
    {
        byte[] rv = Arrays.clone(shared);

        Arrays.fill(shared, (byte)0);

        return rv;
    }

    protected int engineGenerateSecret(byte[] bytes, int offset)
        throws IllegalStateException, ShortBufferException
    {
        System.arraycopy(shared, 0, bytes, offset, shared.length);

        Arrays.fill(shared, (byte)0);

        return shared.length;
    }

    protected byte[] doCalcSecret()
    {
        return engineGenerateSecret();
    }
}
