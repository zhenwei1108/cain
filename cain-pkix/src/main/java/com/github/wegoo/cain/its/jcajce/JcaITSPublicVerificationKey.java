package com.github.wegoo.cain.its.jcajce;

import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;

import com.github.wegoo.cain.asn1.ASN1Encodable;
import com.github.wegoo.cain.asn1.ASN1ObjectIdentifier;
import com.github.wegoo.cain.asn1.nist.NISTNamedCurves;
import com.github.wegoo.cain.asn1.sec.SECObjectIdentifiers;
import com.github.wegoo.cain.asn1.teletrust.TeleTrusTNamedCurves;
import com.github.wegoo.cain.asn1.teletrust.TeleTrusTObjectIdentifiers;
import com.github.wegoo.cain.asn1.x509.SubjectPublicKeyInfo;
import com.github.wegoo.cain.asn1.x9.X9ECParameters;
import com.github.wegoo.cain.its.ITSPublicVerificationKey;
import com.github.wegoo.cain.jcajce.util.DefaultJcaJceHelper;
import com.github.wegoo.cain.jcajce.util.JcaJceHelper;
import com.github.wegoo.cain.jcajce.util.NamedJcaJceHelper;
import com.github.wegoo.cain.jcajce.util.ProviderJcaJceHelper;
import com.github.wegoo.cain.math.ec.ECCurve;
import com.github.wegoo.cain.math.ec.ECPoint;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.EccCurvePoint;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.EccP256CurvePoint;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.EccP384CurvePoint;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.Point256;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.Point384;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.PublicVerificationKey;

public class JcaITSPublicVerificationKey
    extends ITSPublicVerificationKey
{
    public static class Builder
    {
        private JcaJceHelper helper = new DefaultJcaJceHelper();

        public Builder setProvider(Provider provider)
        {
            this.helper = new ProviderJcaJceHelper(provider);

            return this;
        }

        public Builder setProvider(String providerName)
        {
            this.helper = new NamedJcaJceHelper(providerName);

            return this;
        }

        public JcaITSPublicVerificationKey build(PublicVerificationKey verificationKey)
        {
            return new JcaITSPublicVerificationKey(verificationKey, helper);
        }

        public JcaITSPublicVerificationKey build(PublicKey verificationKey)
        {
            return new JcaITSPublicVerificationKey(verificationKey, helper);
        }
    }

    private final JcaJceHelper helper;

    JcaITSPublicVerificationKey(PublicVerificationKey encryptionKey, JcaJceHelper helper)
    {
        super(encryptionKey);
        this.helper = helper;
    }

    JcaITSPublicVerificationKey(PublicKey verificationKey, JcaJceHelper helper)
    {
        super(fromKeyParameters((ECPublicKey)verificationKey));
        this.helper = helper;
    }

    static PublicVerificationKey fromKeyParameters(ECPublicKey pubKey)
    {
        ASN1ObjectIdentifier curveID = ASN1ObjectIdentifier.getInstance(
            SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()).getAlgorithm().getParameters());

        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            return new PublicVerificationKey(
                PublicVerificationKey.ecdsaNistP256,
                EccP256CurvePoint.uncompressedP256(Point256.builder()
                    .setX(pubKey.getW().getAffineX())
                    .setY(pubKey.getW().getAffineY())
                    .createPoint256()));
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            return new PublicVerificationKey(
                PublicVerificationKey.ecdsaBrainpoolP256r1,
                EccP256CurvePoint.uncompressedP256(Point256.builder()
                        .setX(pubKey.getW().getAffineX())
                        .setY(pubKey.getW().getAffineY())
                        .createPoint256())
                    );
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
        {
            return new PublicVerificationKey(
                PublicVerificationKey.ecdsaBrainpoolP384r1,
                EccP384CurvePoint.uncompressedP384(Point384.builder()
                    .setX(pubKey.getW().getAffineX())
                    .setY(pubKey.getW().getAffineY())
                    .createPoint384())
            );
        }
        else
        {
            throw new IllegalArgumentException("unknown curve in public encryption key");
        }
    }

    public PublicKey getKey()
    {
        X9ECParameters params;

        switch (verificationKey.getChoice())
        {
        case PublicVerificationKey.ecdsaNistP256:
            params = NISTNamedCurves.getByOID(SECObjectIdentifiers.secp256r1);
            break;
        case PublicVerificationKey.ecdsaBrainpoolP256r1:
            params = TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP256r1);
            break;
        case PublicVerificationKey.ecdsaBrainpoolP384r1:
            params = TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP384r1);
            break;
        default:
            throw new IllegalStateException("unknown key type");
        }
        ECCurve curve = params.getCurve();

        ASN1Encodable pviCurvePoint = verificationKey.getPublicVerificationKey();
        final EccCurvePoint itsPoint;
        if (pviCurvePoint instanceof EccCurvePoint)
        {
            itsPoint = (EccCurvePoint)verificationKey.getPublicVerificationKey();
        }
        else
        {
            throw new IllegalStateException("extension to public verification key not supported");
        }

        byte[] key;

        if (itsPoint instanceof EccP256CurvePoint)
        {
            key = itsPoint.getEncodedPoint();
        }
        else if (itsPoint instanceof EccP384CurvePoint)
        {
            key = itsPoint.getEncodedPoint();
        }
        else
        {
            throw new IllegalStateException("unknown key type");
        }

        ECPoint point = curve.decodePoint(key).normalize();
        try
        {
            KeyFactory keyFactory = helper.createKeyFactory("EC");
            ECParameterSpec spec = ECUtil.convertToSpec(params);
            java.security.spec.ECPoint jPoint = ECUtil.convertPoint(point);
            return keyFactory.generatePublic(new ECPublicKeySpec(jPoint, spec));
        }
        catch (Exception e)
        {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }
}
