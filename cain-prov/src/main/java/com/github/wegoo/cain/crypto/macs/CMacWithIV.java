package com.github.wegoo.cain.crypto.macs;

import com.github.wegoo.cain.crypto.BlockCipher;
import com.github.wegoo.cain.crypto.CipherParameters;

/**
 * A non-NIST variant which allows passing of an IV to the underlying CBC cipher.
 * <p>Note: there isn't really a good reason to use an IV here, use the regular CMac where possible.</p>
 */
public class CMacWithIV
    extends CMac
{
    public CMacWithIV(BlockCipher cipher)
    {
        super(cipher);
    }

    public CMacWithIV(BlockCipher cipher, int macSizeInBits)
    {
        super(cipher, macSizeInBits);
    }

    void validate(CipherParameters params)
    {
        // accept all
    }
}
