package com.github.wegoo.cain.crypto.agreement;

import java.math.BigInteger;

import com.github.wegoo.cain.crypto.CipherParameters;
import com.github.wegoo.cain.crypto.CryptoServicesRegistrar;
import com.github.wegoo.cain.crypto.StagedAgreement;
import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;
import com.github.wegoo.cain.crypto.params.ECDomainParameters;
import com.github.wegoo.cain.crypto.params.ECPrivateKeyParameters;
import com.github.wegoo.cain.crypto.params.ECPublicKeyParameters;
import com.github.wegoo.cain.math.ec.ECAlgorithms;
import com.github.wegoo.cain.math.ec.ECPoint;

public class ECDHCStagedAgreement
    implements StagedAgreement
{
    ECPrivateKeyParameters key;

    public void init(
        CipherParameters key)
    {
        this.key = (ECPrivateKeyParameters)key;

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties("ECCDH", this.key));
    }

    public int getFieldSize()
    {
        return (key.getParameters().getCurve().getFieldSize() + 7) / 8;
    }

    public AsymmetricKeyParameter calculateStage(
        CipherParameters pubKey)
    {
        ECPoint P = calculateNextPoint((ECPublicKeyParameters)pubKey);

        return new ECPublicKeyParameters(P, key.getParameters());
    }

    public BigInteger calculateAgreement(
        CipherParameters pubKey)
    {
        ECPoint P = calculateNextPoint((ECPublicKeyParameters)pubKey);

        return P.getAffineXCoord().toBigInteger();
    }

    private ECPoint calculateNextPoint(ECPublicKeyParameters pubKey)
    {
        ECPublicKeyParameters pub = pubKey;
        ECDomainParameters params = key.getParameters();
        if (!params.equals(pub.getParameters()))
        {
            throw new IllegalStateException("ECDHC public key has wrong domain parameters");
        }

        BigInteger hd = params.getH().multiply(key.getD()).mod(params.getN());

        // Always perform calculations on the exact curve specified by our private key's parameters
        ECPoint pubPoint = ECAlgorithms.cleanPoint(params.getCurve(), pub.getQ());
        if (pubPoint.isInfinity())
        {
            throw new IllegalStateException("Infinity is not a valid public key for ECDHC");
        }

        ECPoint P = pubPoint.multiply(hd).normalize();

        if (P.isInfinity())
        {
            throw new IllegalStateException("Infinity is not a valid agreement value for ECDHC");
        }

        return P;
    }
}
