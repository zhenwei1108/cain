package com.github.wegoo.cain.pqc.crypto.newhope;

import com.github.wegoo.cain.crypto.CipherParameters;

public class NHAgreement
{
    private NHPrivateKeyParameters privKey;

    public void init(CipherParameters param)
    {
        privKey = (NHPrivateKeyParameters)param;
    }

    public byte[] calculateAgreement(CipherParameters otherPublicKey)
    {
        NHPublicKeyParameters pubKey = (NHPublicKeyParameters)otherPublicKey;

        byte[] sharedValue = new byte[NewHope.AGREEMENT_SIZE];

        NewHope.sharedA(sharedValue, privKey.secData, pubKey.pubData);

        return sharedValue;
    }
}
