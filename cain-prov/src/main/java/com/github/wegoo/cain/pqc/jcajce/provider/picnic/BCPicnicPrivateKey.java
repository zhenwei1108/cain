package com.github.wegoo.cain.pqc.jcajce.provider.picnic;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import com.github.wegoo.cain.asn1.ASN1Set;
import com.github.wegoo.cain.asn1.pkcs.PrivateKeyInfo;
import com.github.wegoo.cain.pqc.crypto.picnic.PicnicPrivateKeyParameters;
import com.github.wegoo.cain.pqc.crypto.util.PrivateKeyFactory;
import com.github.wegoo.cain.pqc.crypto.util.PrivateKeyInfoFactory;
import com.github.wegoo.cain.pqc.jcajce.interfaces.PicnicKey;
import com.github.wegoo.cain.pqc.jcajce.spec.PicnicParameterSpec;
import com.github.wegoo.cain.util.Arrays;

public class BCPicnicPrivateKey
    implements PrivateKey, PicnicKey
{
    private static final long serialVersionUID = 1L;

    private transient PicnicPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCPicnicPrivateKey(
            PicnicPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCPicnicPrivateKey(PrivateKeyInfo keyInfo)
            throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
            throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (PicnicPrivateKeyParameters) PrivateKeyFactory.createKey(keyInfo);
    }

    /**
     * Compare this picnic private key with another object.
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

        if (o instanceof BCPicnicPrivateKey)
        {
            BCPicnicPrivateKey otherKey = (BCPicnicPrivateKey)o;

            return Arrays.areEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    /**
     * @return name of the algorithm - "Picnic"
     */
    public final String getAlgorithm()
    {
        return "Picnic";
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

    public PicnicParameterSpec getParameterSpec()
    {
        return PicnicParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    PicnicPrivateKeyParameters getKeyParams()
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
