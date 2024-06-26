package com.github.wegoo.cain.jcajce.provider.asymmetric.gost;

import java.math.BigInteger;

import com.github.wegoo.cain.crypto.params.GOST3410Parameters;
import com.github.wegoo.cain.util.Arrays;
import com.github.wegoo.cain.util.Fingerprint;
import com.github.wegoo.cain.util.Strings;

class GOSTUtil
{
    static String privateKeyToString(String algorithm, BigInteger x, GOST3410Parameters gostParams)
    {
        StringBuffer buf = new StringBuffer();
        String        nl = Strings.lineSeparator();

        BigInteger y = gostParams.getA().modPow(x, gostParams.getP());

        buf.append(algorithm);
        buf.append(" Private Key [").append(generateKeyFingerprint(y, gostParams)).append("]").append(nl);
        buf.append("                  Y: ").append(y.toString(16)).append(nl);

        return buf.toString();
    }

    static String publicKeyToString(String algorithm, BigInteger y, GOST3410Parameters gostParams)
    {
        StringBuffer buf = new StringBuffer();
        String nl = Strings.lineSeparator();

        buf.append(algorithm);
        buf.append(" Public Key [").append(generateKeyFingerprint(y, gostParams)).append("]").append(nl);
        buf.append("                 Y: ").append(y.toString(16)).append(nl);

        return buf.toString();
    }

    private static String generateKeyFingerprint(BigInteger y, GOST3410Parameters dhParams)
    {
            return new Fingerprint(
                Arrays.concatenate(
                    y.toByteArray(),
                    dhParams.getP().toByteArray(), dhParams.getA().toByteArray())).toString();
    }
}
