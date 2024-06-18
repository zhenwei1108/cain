package com.github.wegoo.cain.pqc.jcajce.provider.ntruprime;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.github.wegoo.cain.asn1.ASN1Primitive;
import com.github.wegoo.cain.asn1.pkcs.PrivateKeyInfo;
import com.github.wegoo.cain.asn1.x509.SubjectPublicKeyInfo;
import com.github.wegoo.cain.jcajce.provider.util.AsymmetricKeyInfoConverter;

public class SNTRUPrimeKeyFactorySpi
    extends KeyFactorySpi
    implements AsymmetricKeyInfoConverter
{
    public PrivateKey engineGeneratePrivate(KeySpec keySpec)
            throws InvalidKeySpecException
    {
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {
            // get the DER-encoded Key according to PKCS#8 from the spec
            byte[] encKey = ((PKCS8EncodedKeySpec)keySpec).getEncoded();

            try
            {
                return generatePrivate(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(encKey)));
            }
            catch (Exception e)
            {
                throw new InvalidKeySpecException(e.toString());
            }
        }

        throw new InvalidKeySpecException("Unsupported key specification: "
                + keySpec.getClass() + ".");
    }

    public PublicKey engineGeneratePublic(KeySpec keySpec)
            throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            // get the DER-encoded Key according to X.509 from the spec
            byte[] encKey = ((X509EncodedKeySpec)keySpec).getEncoded();

            // decode the SubjectPublicKeyInfo data structure to the pki object
            try
            {
                return generatePublic(SubjectPublicKeyInfo.getInstance(encKey));
            }
            catch (Exception e)
            {
                throw new InvalidKeySpecException(e.toString());
            }
        }

        throw new InvalidKeySpecException("Unknown key specification: " + keySpec + ".");
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
            throws InvalidKeySpecException
    {
        if (key instanceof BCSNTRUPrimePrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCSNTRUPrimePublicKey)
        {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new X509EncodedKeySpec(key.getEncoded());
            }
        }
        else
        {
            throw new InvalidKeySpecException("Unsupported key type: "
                    + key.getClass() + ".");
        }

        throw new InvalidKeySpecException("Unknown key specification: "
                + keySpec + ".");
    }

    public final Key engineTranslateKey(Key key)
            throws InvalidKeyException
    {
        if (key instanceof BCNTRULPRimePrivateKey || key instanceof BCNTRULPRimePublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("Unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
    {
        return new BCSNTRUPrimePrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException
    {
        return new BCSNTRUPrimePublicKey(keyInfo);
    }
}
