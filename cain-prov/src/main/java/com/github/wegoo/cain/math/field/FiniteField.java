package com.github.wegoo.cain.math.field;

import java.math.BigInteger;

public interface FiniteField
{
    BigInteger getCharacteristic();

    int getDimension();
}
