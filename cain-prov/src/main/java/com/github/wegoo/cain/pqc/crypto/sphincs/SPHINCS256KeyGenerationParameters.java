package com.github.wegoo.cain.pqc.crypto.sphincs;

import java.security.SecureRandom;

import com.github.wegoo.cain.crypto.Digest;
import com.github.wegoo.cain.crypto.KeyGenerationParameters;

public class SPHINCS256KeyGenerationParameters
    extends KeyGenerationParameters
{
    private final Digest treeDigest;

    public SPHINCS256KeyGenerationParameters(SecureRandom random, Digest treeDigest)
    {
        super(random, SPHINCS256Config.CRYPTO_PUBLICKEYBYTES * 8);
        this.treeDigest = treeDigest;
    }

    public Digest getTreeDigest()
    {
        return treeDigest;
    }
}
