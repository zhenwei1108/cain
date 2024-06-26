package com.github.wegoo.cain.pqc.legacy.crypto.mceliece;

import java.security.SecureRandom;

import com.github.wegoo.cain.crypto.KeyGenerationParameters;

public class McElieceKeyGenerationParameters
    extends KeyGenerationParameters
{
    private McElieceParameters params;

    public McElieceKeyGenerationParameters(
        SecureRandom random,
        McElieceParameters params)
    {
        // XXX key size?
        super(random, 256);
        this.params = params;
    }

    public McElieceParameters getParameters()
    {
        return params;
    }
}
