package com.github.wegoo.cain.crypto.modes;

import com.github.wegoo.cain.crypto.BlockCipher;

/**
 * An {@link AEADCipher} based on a {@link BlockCipher}.
 */
public interface AEADBlockCipher
    extends AEADCipher
{
    /**
     * return the {@link BlockCipher} this object wraps.
     *
     * @return the {@link BlockCipher} this object wraps.
     */
    public BlockCipher getUnderlyingCipher();
}
