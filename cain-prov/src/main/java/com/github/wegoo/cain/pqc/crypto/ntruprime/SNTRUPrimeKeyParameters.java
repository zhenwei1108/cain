package com.github.wegoo.cain.pqc.crypto.ntruprime;

import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;

public class SNTRUPrimeKeyParameters
    extends AsymmetricKeyParameter
{
    private final SNTRUPrimeParameters params;

    public SNTRUPrimeKeyParameters(boolean privateKey, SNTRUPrimeParameters params)
    {
        super(privateKey);
        this.params = params;
    }

    public SNTRUPrimeParameters getParameters()
    {
        return params;
    }
}
