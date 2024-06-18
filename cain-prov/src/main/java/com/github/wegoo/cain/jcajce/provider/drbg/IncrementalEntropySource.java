package com.github.wegoo.cain.jcajce.provider.drbg;

import com.github.wegoo.cain.crypto.prng.EntropySource;

interface IncrementalEntropySource
    extends EntropySource
{
    /**
     * Pause allows for a gap between fetches. We only want this after we've initialised.
     *
     * @param pause time in milliseconds to pause in build up seed.
     * @return the resulting seed
     */
    byte[] getEntropy(long pause)
        throws InterruptedException;
}
