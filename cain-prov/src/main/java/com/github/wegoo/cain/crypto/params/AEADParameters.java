package com.github.wegoo.cain.crypto.params;

import com.github.wegoo.cain.crypto.CipherParameters;
import com.github.wegoo.cain.util.Arrays;

public class AEADParameters
    implements CipherParameters
{
    private byte[] associatedText;
    private byte[] nonce;
    private KeyParameter key;
    private int macSize;

    /**
     * Base constructor.
     *
     * @param key key to be used by underlying cipher
     * @param macSize macSize in bits
     * @param nonce nonce to be used
     */
   public AEADParameters(KeyParameter key, int macSize, byte[] nonce)
    {
       this(key, macSize, nonce, null);
    }

    /**
     * Base constructor.
     *
     * @param key key to be used by underlying cipher
     * @param macSize macSize in bits
     * @param nonce nonce to be used
     * @param associatedText initial associated text, if any
     */
    public AEADParameters(KeyParameter key, int macSize, byte[] nonce, byte[] associatedText)
    {
        this.key = key;
        this.nonce = Arrays.clone(nonce);
        this.macSize = macSize;
        this.associatedText = Arrays.clone(associatedText);
    }

    public KeyParameter getKey()
    {
        return key;
    }

    public int getMacSize()
    {
        return macSize;
    }

    public byte[] getAssociatedText()
    {
        return Arrays.clone(associatedText);
    }

    public byte[] getNonce()
    {
        return Arrays.clone(nonce);
    }
}
