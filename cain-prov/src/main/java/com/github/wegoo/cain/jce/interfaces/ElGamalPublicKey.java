package com.github.wegoo.cain.jce.interfaces;

import java.math.BigInteger;

import javax.crypto.interfaces.DHPublicKey;

public interface ElGamalPublicKey
    extends ElGamalKey, DHPublicKey
{
    public BigInteger getY();
}
