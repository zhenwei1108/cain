package com.github.wegoo.cain.pqc.jcajce.provider.newhope;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import com.github.wegoo.cain.asn1.x509.SubjectPublicKeyInfo;
import com.github.wegoo.cain.crypto.CipherParameters;
import com.github.wegoo.cain.pqc.crypto.newhope.NHPublicKeyParameters;
import com.github.wegoo.cain.pqc.crypto.util.PublicKeyFactory;
import com.github.wegoo.cain.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import com.github.wegoo.cain.pqc.jcajce.interfaces.NHPublicKey;
import com.github.wegoo.cain.util.Arrays;

public class BCNHPublicKey
    implements NHPublicKey
{
    private static final long serialVersionUID = 1L;

    private transient NHPublicKeyParameters params;

    public BCNHPublicKey(
        NHPublicKeyParameters params)
    {
        this.params = params;
    }

    public BCNHPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.params = (NHPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
    }

    /**
     * Compare this SPHINCS-256 public key with another object.
     *
     * @param o the other object
     * @return the result of the comparison
     */
    public boolean equals(Object o)
    {
        if (o == null || !(o instanceof BCNHPublicKey))
        {
            return false;
        }
        BCNHPublicKey otherKey = (BCNHPublicKey)o;

        return Arrays.areEqual(params.getPubData(), otherKey.params.getPubData());
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getPubData());
    }

    /**
     * @return name of the algorithm - "NH"
     */
    public final String getAlgorithm()
    {
        return "NH";
    }

    public byte[] getEncoded()
    {
        try
        {
            SubjectPublicKeyInfo pki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(params);

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

    public byte[] getPublicData()
    {
        return params.getPubData();
    }

    CipherParameters getKeyParams()
    {
        return params;
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
