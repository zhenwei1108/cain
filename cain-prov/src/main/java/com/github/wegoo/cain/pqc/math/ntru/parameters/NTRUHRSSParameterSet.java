package com.github.wegoo.cain.pqc.math.ntru.parameters;

import com.github.wegoo.cain.pqc.math.ntru.HRSS1373Polynomial;
import com.github.wegoo.cain.pqc.math.ntru.HRSSPolynomial;
import com.github.wegoo.cain.pqc.math.ntru.Polynomial;

/**
 * Abstract class for NTRU-HRSS parameter classes.
 * <p>
 * The naming convention for the classes is {@code NTRUHRSS[n]}. e.g. {@link NTRUHRSS701} has n = 701.
 *
 * @see NTRUHRSS701
 * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification document</a> section 1.3.3
 */
public abstract class NTRUHRSSParameterSet
    extends NTRUParameterSet
{
    NTRUHRSSParameterSet(int n, int logQ, int seedBytes, int prfKeyBytes, int sharedKeyBytes)
    {
        super(n, logQ, seedBytes, prfKeyBytes, sharedKeyBytes);
    }

    @Override
    public Polynomial createPolynomial()
    {
        return this.n() == 1373 ? new HRSS1373Polynomial(this) : new HRSSPolynomial(this);
    }

    @Override
    public int sampleFgBytes()
    {
        return 2 * sampleIidBytes();
    }

    @Override
    public int sampleRmBytes()
    {
        return 2 * sampleIidBytes();
    }
}
