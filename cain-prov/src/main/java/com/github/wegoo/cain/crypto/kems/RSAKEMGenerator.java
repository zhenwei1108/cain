package com.github.wegoo.cain.crypto.kems;

import java.math.BigInteger;
import java.security.SecureRandom;

import com.github.wegoo.cain.crypto.CryptoServicePurpose;
import com.github.wegoo.cain.crypto.CryptoServicesRegistrar;
import com.github.wegoo.cain.crypto.DerivationFunction;
import com.github.wegoo.cain.crypto.EncapsulatedSecretGenerator;
import com.github.wegoo.cain.crypto.SecretWithEncapsulation;
import com.github.wegoo.cain.crypto.constraints.ConstraintUtils;
import com.github.wegoo.cain.crypto.constraints.DefaultServiceProperties;
import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;
import com.github.wegoo.cain.crypto.params.KDFParameters;
import com.github.wegoo.cain.crypto.params.RSAKeyParameters;
import com.github.wegoo.cain.util.BigIntegers;

/**
 * The RSA Key Encapsulation Mechanism (RSA-KEM) from ISO 18033-2.
 */
public class RSAKEMGenerator
    implements EncapsulatedSecretGenerator
{
    private static final BigInteger ZERO = BigInteger.valueOf(0);
    private static final BigInteger ONE = BigInteger.valueOf(1);

    private final int keyLen;
    private DerivationFunction kdf;
    private SecureRandom rnd;

    /**
     * Set up the RSA-KEM.
     *
     * @param kdf the key derivation function to be used.
     * @param rnd the random source for the session key.
     */
    public RSAKEMGenerator(
        int keyLen,
        DerivationFunction kdf,
        SecureRandom rnd)
    {
        this.keyLen = keyLen;
        this.kdf = kdf;
        this.rnd = rnd;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        RSAKeyParameters key = (RSAKeyParameters)recipientKey;

        if (key.isPrivate())
        {
            throw new IllegalArgumentException("public key required for encryption");
        }

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("RSAKem",
                    ConstraintUtils.bitsOfSecurityFor(key.getModulus()), key, CryptoServicePurpose.ENCRYPTION));

        BigInteger n = key.getModulus();
        BigInteger e = key.getExponent();

        // Generate the ephemeral random and encode it
        BigInteger r = BigIntegers.createRandomInRange(ZERO, n.subtract(ONE), rnd);

        // Encrypt the random and encode it
        BigInteger c = r.modPow(e, n);
        byte[] C = BigIntegers.asUnsignedByteArray((n.bitLength() + 7) / 8, c);

        return new SecretWithEncapsulationImpl(generateKey(kdf, n, r, keyLen), C);
    }

    static byte[] generateKey(DerivationFunction kdf, BigInteger n, BigInteger r, int keyLen)
    {
        byte[] R = BigIntegers.asUnsignedByteArray((n.bitLength() + 7) / 8, r);

        // Initialise the KDF
        kdf.init(new KDFParameters(R, null));

        // Generate the secret key
        byte[] K = new byte[keyLen];
        kdf.generateBytes(K, 0, K.length);

        return K;
    }
}
