package com.github.wegoo.cain.pqc.jcajce.provider.frodo;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import com.github.wegoo.cain.asn1.ASN1Set;
import com.github.wegoo.cain.asn1.pkcs.PrivateKeyInfo;
import com.github.wegoo.cain.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import com.github.wegoo.cain.pqc.crypto.util.PrivateKeyFactory;
import com.github.wegoo.cain.pqc.crypto.util.PrivateKeyInfoFactory;
import com.github.wegoo.cain.pqc.jcajce.interfaces.FrodoKey;
import com.github.wegoo.cain.pqc.jcajce.spec.FrodoParameterSpec;
import com.github.wegoo.cain.util.Arrays;

public class BCFrodoPrivateKey
    implements PrivateKey, FrodoKey
{
    private static final long serialVersionUID = 1L;

    private transient FrodoPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCFrodoPrivateKey(
            FrodoPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCFrodoPrivateKey(PrivateKeyInfo keyInfo)
            throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
            throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (FrodoPrivateKeyParameters) PrivateKeyFactory.createKey(keyInfo);
    }

    /**
     * Compare this private key with another object.
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

        if (o instanceof BCFrodoPrivateKey)
        {
            BCFrodoPrivateKey otherKey = (BCFrodoPrivateKey)o;

            return Arrays.areEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    /**
     * @return name of the algorithm - "Frodo"
     */
    public final String getAlgorithm()
    {
        return "Frodo";
    }

    public byte[] getEncoded()
    {

        try
        {
            PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(params, attributes);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public FrodoParameterSpec getParameterSpec()
    {
        return FrodoParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    FrodoPrivateKeyParameters getKeyParams()
    {
        return params;
    }

    private void readObject(
            ObjectInputStream in)
            throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(
            ObjectOutputStream out)
            throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
