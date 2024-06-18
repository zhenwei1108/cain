package com.github.wegoo.cain.pqc.jcajce.provider.cmce;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import com.github.wegoo.cain.asn1.ASN1Set;
import com.github.wegoo.cain.asn1.pkcs.PrivateKeyInfo;
import com.github.wegoo.cain.pqc.crypto.cmce.CMCEPrivateKeyParameters;
import com.github.wegoo.cain.pqc.crypto.util.PrivateKeyFactory;
import com.github.wegoo.cain.pqc.crypto.util.PrivateKeyInfoFactory;
import com.github.wegoo.cain.pqc.jcajce.interfaces.CMCEKey;
import com.github.wegoo.cain.pqc.jcajce.spec.CMCEParameterSpec;
import com.github.wegoo.cain.util.Arrays;
import com.github.wegoo.cain.util.Strings;

public class BCCMCEPrivateKey
    implements PrivateKey, CMCEKey
{
    private static final long serialVersionUID = 1L;

    private transient CMCEPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCCMCEPrivateKey(
        CMCEPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCCMCEPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (CMCEPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
    }

    /**
     * Compare this SPHINCS-256 private key with another object.
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

        if (o instanceof BCCMCEPrivateKey)
        {
            BCCMCEPrivateKey otherKey = (BCCMCEPrivateKey)o;

            return Arrays.areEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    /**
     * @return name of the algorithm - "CMCE"
     */
    public final String getAlgorithm()
    {
        return Strings.toUpperCase(params.getParameters().getName());
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

    public CMCEParameterSpec getParameterSpec()
    {
        return CMCEParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    CMCEPrivateKeyParameters getKeyParams()
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
