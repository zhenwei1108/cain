package com.github.wegoo.cain.pqc.jcajce.provider.sphincs;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

import com.github.wegoo.cain.asn1.ASN1ObjectIdentifier;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.asn1.x509.SubjectPublicKeyInfo;
import com.github.wegoo.cain.crypto.CipherParameters;
import com.github.wegoo.cain.pqc.asn1.PQCObjectIdentifiers;
import com.github.wegoo.cain.pqc.asn1.SPHINCS256KeyParams;
import com.github.wegoo.cain.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import com.github.wegoo.cain.pqc.crypto.util.PublicKeyFactory;
import com.github.wegoo.cain.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import com.github.wegoo.cain.pqc.jcajce.interfaces.SPHINCSKey;
import com.github.wegoo.cain.util.Arrays;

public class BCSphincs256PublicKey
    implements PublicKey, SPHINCSKey
{
    private static final long serialVersionUID = 1L;

    private transient ASN1ObjectIdentifier treeDigest;
    private transient SPHINCSPublicKeyParameters params;

    public BCSphincs256PublicKey(
        ASN1ObjectIdentifier treeDigest,
        SPHINCSPublicKeyParameters params)
    {
        this.treeDigest = treeDigest;
        this.params = params;
    }

    public BCSphincs256PublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.treeDigest = SPHINCS256KeyParams.getInstance(keyInfo.getAlgorithm().getParameters()).getTreeDigest().getAlgorithm();
        this.params = (SPHINCSPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
    }
    
    /**
     * Compare this SPHINCS-256 public key with another object.
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

        if (o instanceof BCSphincs256PublicKey)
        {
            BCSphincs256PublicKey otherKey = (BCSphincs256PublicKey)o;

            return treeDigest.equals(otherKey.treeDigest) && Arrays.areEqual(params.getKeyData(), otherKey.params.getKeyData());
        }

        return false;
    }

    public int hashCode()
    {
        return treeDigest.hashCode() + 37 * Arrays.hashCode(params.getKeyData());
    }

    /**
     * @return name of the algorithm - "SPHINCS-256"
     */
    public final String getAlgorithm()
    {
        return "SPHINCS-256";
    }

    public byte[] getEncoded()
    {
        try
        {
            SubjectPublicKeyInfo pki;

            if (params.getTreeDigest() != null)
            {
                pki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(params);
            }
            else
            {
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.sphincs256, new SPHINCS256KeyParams(new AlgorithmIdentifier(treeDigest)));
                pki = new SubjectPublicKeyInfo(algorithmIdentifier, params.getKeyData());
            }

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

    public byte[] getKeyData()
    {
        return params.getKeyData();
    }

    ASN1ObjectIdentifier getTreeDigest()
    {
        return treeDigest;
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
