package com.github.wegoo.cain.jcajce.provider.asymmetric.ecgost12;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import com.github.wegoo.cain.crypto.CipherParameters;
import com.github.wegoo.cain.crypto.DerivationFunction;
import com.github.wegoo.cain.crypto.agreement.ECVKOAgreement;
import com.github.wegoo.cain.crypto.digests.GOST3411_2012_256Digest;
import com.github.wegoo.cain.crypto.params.AsymmetricKeyParameter;
import com.github.wegoo.cain.crypto.params.ECDomainParameters;
import com.github.wegoo.cain.crypto.params.ECPrivateKeyParameters;
import com.github.wegoo.cain.crypto.params.ParametersWithUKM;
import com.github.wegoo.cain.jcajce.provider.asymmetric.util.BaseAgreementSpi;
import com.github.wegoo.cain.jcajce.provider.asymmetric.util.ECUtil;
import com.github.wegoo.cain.jcajce.spec.UserKeyingMaterialSpec;
import com.github.wegoo.cain.jce.interfaces.ECPrivateKey;
import com.github.wegoo.cain.jce.interfaces.ECPublicKey;

public class KeyAgreementSpi
    extends BaseAgreementSpi
{
    private String                 kaAlgorithm;

    private ECDomainParameters     parameters;
    private ECVKOAgreement agreement;

    private byte[]             result;

    protected KeyAgreementSpi(
        String kaAlgorithm,
        ECVKOAgreement agreement,
        DerivationFunction kdf)
    {
        super(kaAlgorithm, kdf);

        this.kaAlgorithm = kaAlgorithm;
        this.agreement = agreement;
    }

    protected Key engineDoPhase(
        Key     key,
        boolean lastPhase) 
        throws InvalidKeyException, IllegalStateException
    {
        if (parameters == null)
        {
            throw new IllegalStateException(kaAlgorithm + " not initialised.");
        }

        if (!lastPhase)
        {
            throw new IllegalStateException(kaAlgorithm + " can only be between two parties.");
        }

        CipherParameters pubKey;
        {
            if (!(key instanceof PublicKey))
            {
                throw new InvalidKeyException(kaAlgorithm + " key agreement requires "
                    + getSimpleName(ECPublicKey.class) + " for doPhase");
            }

            pubKey = generatePublicKeyParameter((PublicKey)key);
        }

        try
        {
            result = agreement.calculateAgreement(pubKey);
        }
        catch (final Exception e)
        {
            throw new InvalidKeyException("calculation failed: " + e.getMessage())
            {
                public Throwable getCause()
                            {
                                return e;
                            }
            };
        }

        return null;
    }

    protected void doInitFromKey(Key key, AlgorithmParameterSpec parameterSpec, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (!(key instanceof PrivateKey))
        {
            throw new InvalidKeyException(kaAlgorithm + " key agreement requires "
                + getSimpleName(ECPrivateKey.class) + " for initialisation");
        }

        if (parameterSpec != null && !(parameterSpec instanceof UserKeyingMaterialSpec))
        {
            throw new InvalidAlgorithmParameterException("No algorithm parameters supported");
        }

        ECPrivateKeyParameters privKey = (ECPrivateKeyParameters)ECUtil.generatePrivateKeyParameter((PrivateKey)key);
        this.parameters = privKey.getParameters();
        ukmParameters = (parameterSpec instanceof UserKeyingMaterialSpec) ? ((UserKeyingMaterialSpec)parameterSpec).getUserKeyingMaterial() : null;
        agreement.init(new ParametersWithUKM(privKey, ukmParameters));
    }

    private static String getSimpleName(Class clazz)
    {
        String fullName = clazz.getName();

        return fullName.substring(fullName.lastIndexOf('.') + 1);
    }

    static AsymmetricKeyParameter generatePublicKeyParameter(
            PublicKey key)
        throws InvalidKeyException
    {
        return (key instanceof BCECGOST3410_2012PublicKey) ? ((BCECGOST3410_2012PublicKey)key).engineGetKeyParameters() : ECUtil.generatePublicKeyParameter(key);
    }

    protected byte[] doCalcSecret()
    {
        return result;
    }

    public static class ECVKO256
        extends KeyAgreementSpi
    {
        public ECVKO256()
        {
            super("ECGOST3410-2012-256", new ECVKOAgreement(new GOST3411_2012_256Digest()), null);
        }
    }

    public static class ECVKO512
        extends KeyAgreementSpi
    {
        public ECVKO512()
        {
            super("ECGOST3410-2012-512", new ECVKOAgreement(new GOST3411_2012_256Digest()), null);
        }
    }
}
