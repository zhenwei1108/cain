package com.github.wegoo.cain.pqc.jcajce.provider.util;

import com.github.wegoo.cain.asn1.ASN1Encodable;
import com.github.wegoo.cain.asn1.ASN1Encoding;
import com.github.wegoo.cain.asn1.ASN1Set;
import com.github.wegoo.cain.asn1.pkcs.PrivateKeyInfo;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.asn1.x509.SubjectPublicKeyInfo;
import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;
import com.github.wegoo.cain.pqc.crypto.util.PrivateKeyInfoFactory;
import com.github.wegoo.cain.pqc.crypto.util.SubjectPublicKeyInfoFactory;

public class KeyUtil
{
    public static byte[] getEncodedSubjectPublicKeyInfo(AlgorithmIdentifier algId, ASN1Encodable keyData)
    {
        try
        {
            return getEncodedSubjectPublicKeyInfo(new SubjectPublicKeyInfo(algId, keyData));
        }
        catch (Exception e)
        {
            return null;
        }
    }

    public static byte[] getEncodedSubjectPublicKeyInfo(AlgorithmIdentifier algId, byte[] keyData)
    {
        try
        {
            return getEncodedSubjectPublicKeyInfo(new SubjectPublicKeyInfo(algId, keyData));
        }
        catch (Exception e)
        {
            return null;
        }
    }

    public static byte[] getEncodedSubjectPublicKeyInfo(SubjectPublicKeyInfo info)
    {
         try
         {
             return info.getEncoded(ASN1Encoding.DER);
         }
         catch (Exception e)
         {
             return null;
         }
    }

    public static byte[] getEncodedSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
    {
        if (publicKey.isPrivate())
        {
            throw new IllegalArgumentException("private key found");
        }

        try
        {
            return getEncodedSubjectPublicKeyInfo(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey));
        }
        catch (Exception e)
        {
            return null;
        }
    }

    public static byte[] getEncodedPrivateKeyInfo(AlgorithmIdentifier algId, ASN1Encodable privKey)
    {
         try
         {
             PrivateKeyInfo info = new PrivateKeyInfo(algId, privKey.toASN1Primitive());

             return getEncodedPrivateKeyInfo(info);
         }
         catch (Exception e)
         {
             return null;
         }
    }

    public static byte[] getEncodedPrivateKeyInfo(PrivateKeyInfo info)
    {
         try
         {
             return info.getEncoded(ASN1Encoding.DER);
         }
         catch (Exception e)
         {
             return null;
         }
    }

    public static byte[] getEncodedPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes)
    {
        if (!privateKey.isPrivate())
        {
            throw new IllegalArgumentException("public key found");
        }

        try
        {
            return getEncodedPrivateKeyInfo(PrivateKeyInfoFactory.createPrivateKeyInfo(privateKey, attributes));
        }
        catch (Exception e)
        {
            return null;
        }
    }
}
