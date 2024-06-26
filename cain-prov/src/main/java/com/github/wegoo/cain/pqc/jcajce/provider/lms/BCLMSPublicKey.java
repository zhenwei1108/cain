package com.github.wegoo.cain.pqc.jcajce.provider.lms;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

import com.github.wegoo.cain.asn1.x509.SubjectPublicKeyInfo;
import com.github.wegoo.cain.crypto.CipherParameters;
import com.github.wegoo.cain.pqc.crypto.lms.HSSPublicKeyParameters;
import com.github.wegoo.cain.pqc.crypto.lms.LMSKeyParameters;
import com.github.wegoo.cain.pqc.crypto.lms.LMSPublicKeyParameters;
import com.github.wegoo.cain.pqc.crypto.util.PublicKeyFactory;
import com.github.wegoo.cain.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import com.github.wegoo.cain.pqc.jcajce.interfaces.LMSKey;
import com.github.wegoo.cain.util.Arrays;
import com.github.wegoo.cain.util.Encodable;

public class BCLMSPublicKey
    implements PublicKey, LMSKey
{
    private static final long serialVersionUID = -5617456225328969766L;
    
    private transient LMSKeyParameters keyParams;

    public BCLMSPublicKey(
        LMSKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    public BCLMSPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.keyParams = (LMSKeyParameters)PublicKeyFactory.createKey(keyInfo);
    }

    /**
     * @return name of the algorithm - "LMS"
     */
    public final String getAlgorithm()
    {
        return "LMS";
    }

    public byte[] getEncoded()
    {
        try
        {
            SubjectPublicKeyInfo pki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyParams);
            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public String getFormat()
    {
        return "X.509";
    }

    CipherParameters getKeyParams()
    {
        return keyParams;
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCLMSPublicKey)
        {
            BCLMSPublicKey otherKey = (BCLMSPublicKey)o;

            try
            {
                return Arrays.areEqual(keyParams.getEncoded(), otherKey.keyParams.getEncoded());
            }
            catch (IOException e)
            {
                return false;
            }
        }

        return false;
    }

    public int hashCode()
    {
        try
        {
            return Arrays.hashCode(((Encodable)keyParams).getEncoded());
        }
        catch (IOException e)
        {
            // should never happen, but...
            return -1;
        }
    }
    
    public int getLevels()
    {
        if (keyParams instanceof LMSPublicKeyParameters)
        {
            return 1;
        }
        else
        {
            return ((HSSPublicKeyParameters)keyParams).getL();
        }
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(SubjectPublicKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
