package com.github.wegoo.cain.pqc.crypto.hqc;

import com.github.wegoo.cain.util.Arrays;

public class HQCPrivateKeyParameters
    extends HQCKeyParameters
{
    private byte[] sk;

    public HQCPrivateKeyParameters(HQCParameters params, byte[] sk)
    {
        super(true, params);
        this.sk = Arrays.clone(sk);
    }

    public byte[] getPrivateKey()
    {
        return Arrays.clone(this.sk);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(this.sk);
    }
}
