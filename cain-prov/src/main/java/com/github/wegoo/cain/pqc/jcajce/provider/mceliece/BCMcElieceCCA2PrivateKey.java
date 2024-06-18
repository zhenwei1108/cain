package com.github.wegoo.cain.pqc.jcajce.provider.mceliece;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import com.github.wegoo.cain.asn1.pkcs.PrivateKeyInfo;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;
import com.github.wegoo.cain.jcajce.util.MessageDigestUtils;
import com.github.wegoo.cain.pqc.asn1.McElieceCCA2PrivateKey;
import com.github.wegoo.cain.pqc.asn1.PQCObjectIdentifiers;
import com.github.wegoo.cain.pqc.crypto.util.PrivateKeyFactory;
import com.github.wegoo.cain.pqc.legacy.crypto.mceliece.McElieceCCA2KeyPairGenerator;
import com.github.wegoo.cain.pqc.legacy.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
import com.github.wegoo.cain.pqc.legacy.math.linearalgebra.GF2Matrix;
import com.github.wegoo.cain.pqc.legacy.math.linearalgebra.GF2mField;
import com.github.wegoo.cain.pqc.legacy.math.linearalgebra.Permutation;
import com.github.wegoo.cain.pqc.legacy.math.linearalgebra.PolynomialGF2mSmallM;

/**
 * This class implements a McEliece CCA2 private key and is usually instantiated
 * by the {@link McElieceCCA2KeyPairGenerator} or {@link McElieceCCA2KeyFactorySpi}.
 *
 * @see McElieceCCA2KeyPairGenerator
 */
public class BCMcElieceCCA2PrivateKey
    implements PrivateKey
{
    private static final long serialVersionUID = 1L;

    private transient McElieceCCA2PrivateKeyParameters params;

    public BCMcElieceCCA2PrivateKey(McElieceCCA2PrivateKeyParameters params)
    {
        this.params = params;
    }

    private void init(PrivateKeyInfo privateKeyInfo)
        throws IOException
    {
        this.params = (McElieceCCA2PrivateKeyParameters)PrivateKeyFactory.createKey(privateKeyInfo);
    }

    /**
     * Return the name of the algorithm.
     *
     * @return "McEliece-CCA2"
     */
    public String getAlgorithm()
    {
        return "McEliece-CCA2";
    }

    /**
     * @return the length of the code
     */
    public int getN()
    {
        return params.getN();
    }

    /**
     * @return the dimension of the code
     */
    public int getK()
    {
        return params.getK();
    }

    /**
     * @return the degree of the Goppa polynomial (error correcting capability)
     */
    public int getT()
    {
        return params.getGoppaPoly().getDegree();
    }

    /**
     * @return the finite field
     */
    public GF2mField getField()
    {
        return params.getField();
    }

    /**
     * @return the irreducible Goppa polynomial
     */
    public PolynomialGF2mSmallM getGoppaPoly()
    {
        return params.getGoppaPoly();
    }

    /**
     * @return the permutation vector
     */
    public Permutation getP()
    {
        return params.getP();
    }

    /**
     * @return the canonical check matrix
     */
    public GF2Matrix getH()
    {
        return params.getH();
    }

    /**
     * @return the matrix used to compute square roots in <tt>(GF(2^m))^t</tt>
     */
    public PolynomialGF2mSmallM[] getQInv()
    {
        return params.getQInv();
    }

    /**
     * @return a human readable form of the key
     */
    // TODO:
//    public String toString()
//    {
//        String result = "";
//        result += " extension degree of the field      : " + getN() + "\n";
//        result += " dimension of the code              : " + getK() + "\n";
//        result += " irreducible Goppa polynomial       : " + getGoppaPoly() + "\n";
//        return result;
//    }

    /**
     * Compare this key with another object.
     *
     * @param other the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other)
    {
        if (other == null || !(other instanceof BCMcElieceCCA2PrivateKey))
        {
            return false;
        }

        BCMcElieceCCA2PrivateKey otherKey = (BCMcElieceCCA2PrivateKey)other;

        return (getN() == otherKey.getN()) && (getK() == otherKey.getK())
            && getField().equals(otherKey.getField())
            && getGoppaPoly().equals(otherKey.getGoppaPoly()) && getP().equals(otherKey.getP())
            && getH().equals(otherKey.getH());
    }

    /**
     * @return the hash code of this key
     */
    public int hashCode()
    {
        int code = params.getK();

        code = code * 37 + params.getN();
        code = code * 37 + params.getField().hashCode();
        code = code * 37 + params.getGoppaPoly().hashCode();
        code = code * 37 + params.getP().hashCode();

        return code * 37 + params.getH().hashCode();
    }

    /**
     * Return the keyData to encode in the SubjectPublicKeyInfo structure.
     * <p>
     * The ASN.1 definition of the key structure is
     * <pre>
     *   McEliecePrivateKey ::= SEQUENCE {
     *     m             INTEGER                  -- extension degree of the field
     *     k             INTEGER                  -- dimension of the code
     *     field         OCTET STRING             -- field polynomial
     *     goppaPoly     OCTET STRING             -- irreducible Goppa polynomial
     *     p             OCTET STRING             -- permutation vector
     *     matrixH       OCTET STRING             -- canonical check matrix
     *     sqRootMatrix  SEQUENCE OF OCTET STRING -- square root matrix
     *   }
     * </pre>
     * @return the keyData to encode in the SubjectPublicKeyInfo structure
     */
    public byte[] getEncoded()
    {
        PrivateKeyInfo pki;
        try
        {
            McElieceCCA2PrivateKey privateKey = new McElieceCCA2PrivateKey(getN(), getK(), getField(), getGoppaPoly(), getP(), MessageDigestUtils.getDigestAlgID(params.getDigest()));
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.mcElieceCca2);

            pki = new PrivateKeyInfo(algorithmIdentifier, privateKey);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    AsymmetricKeyParameter getKeyParams()
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
