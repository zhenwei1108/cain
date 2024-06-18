package com.github.wegoo.cain.pqc.jcajce.provider.ntru;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

import com.github.wegoo.cain.asn1.x509.SubjectPublicKeyInfo;
import com.github.wegoo.cain.pqc.crypto.ntru.NTRUPublicKeyParameters;
import com.github.wegoo.cain.pqc.crypto.util.PublicKeyFactory;
import com.github.wegoo.cain.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import com.github.wegoo.cain.pqc.jcajce.interfaces.NTRUKey;
import com.github.wegoo.cain.pqc.jcajce.spec.NTRUParameterSpec;
import com.github.wegoo.cain.util.Arrays;

public class BCNTRUPublicKey
    implements PublicKey, NTRUKey
{
    private static final long serialVersionUID = 1L;

    private transient NTRUPublicKeyParameters params;

    public BCNTRUPublicKey(
        NTRUPublicKeyParameters params)
    {
        this.params = params;
    }

    public BCNTRUPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.params = (NTRUPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
    }

    /**
     * Compare this NTRU public key with another object.
     *
     * @param o the other object
     * @return the result of the comparison
     */
    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCNTRUPublicKey)
        {
            BCNTRUPublicKey otherKey = (BCNTRUPublicKey)o;

            return Arrays.areEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    /**
     * @return name of the algorithm - "NTRU"
     */
    public final String getAlgorithm()
    {
        return "NTRU";
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

    public NTRUParameterSpec getParameterSpec()
    {
        return NTRUParameterSpec.fromName(params.getParameters().getName());
    }

    NTRUPublicKeyParameters getKeyParams()
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
