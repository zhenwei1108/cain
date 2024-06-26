package com.github.wegoo.cain.pqc.crypto.xmss;

import java.security.SecureRandom;

import com.github.wegoo.cain.crypto.KeyGenerationParameters;

/**
 * XMSS key-pair generation parameters.
 */
public final class XMSSKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final XMSSParameters xmssParameters;

    /**
     * XMSSMT constructor...
     *
     * @param prng   Secure random to use.
     */
    public XMSSKeyGenerationParameters(XMSSParameters xmssParameters, SecureRandom prng)
    {
        super(prng,-1);

        this.xmssParameters = xmssParameters;
    }

    public XMSSParameters getParameters()
    {
        return xmssParameters;
    }
}
