package com.github.wegoo.cain.its.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

import com.github.wegoo.cain.asn1.nist.NISTObjectIdentifiers;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.its.ITSCertificate;
import com.github.wegoo.cain.its.ITSPublicVerificationKey;
import com.github.wegoo.cain.its.operator.ITSContentVerifierProvider;
import com.github.wegoo.cain.jcajce.util.DefaultJcaJceHelper;
import com.github.wegoo.cain.jcajce.util.JcaJceHelper;
import com.github.wegoo.cain.jcajce.util.NamedJcaJceHelper;
import com.github.wegoo.cain.jcajce.util.ProviderJcaJceHelper;
import com.github.wegoo.cain.oer.OEREncoder;
import com.github.wegoo.cain.oer.its.ieee1609dot2.ToBeSignedCertificate;
import com.github.wegoo.cain.oer.its.ieee1609dot2.VerificationKeyIndicator;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.PublicVerificationKey;
import com.github.wegoo.cain.oer.its.template.ieee1609dot2.IEEE1609dot2;
import com.github.wegoo.cain.operator.ContentVerifier;
import com.github.wegoo.cain.operator.DigestCalculator;
import com.github.wegoo.cain.operator.DigestCalculatorProvider;
import com.github.wegoo.cain.operator.OperatorCreationException;
import com.github.wegoo.cain.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import com.github.wegoo.cain.util.Arrays;

public class JcaITSContentVerifierProvider
    implements ITSContentVerifierProvider
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

        public JcaITSContentVerifierProvider build(ITSCertificate issuer)
        {
            return new JcaITSContentVerifierProvider(issuer, helper);
        }

        public JcaITSContentVerifierProvider build(ITSPublicVerificationKey issuer)
        {
            return new JcaITSContentVerifierProvider(issuer, helper);
        }
    }

    private final ITSCertificate issuer;
    private final byte[] parentData;
    private final JcaJceHelper helper;

    private AlgorithmIdentifier digestAlgo;
    private ECPublicKey pubParams;
    private int sigChoice;

    private JcaITSContentVerifierProvider(ITSCertificate issuer, JcaJceHelper helper)
    {
        this.issuer = issuer;
        this.helper = helper;
        try
        {
            this.parentData = issuer.getEncoded();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to extract parent data: " + e.getMessage());
        }
        ToBeSignedCertificate toBeSignedCertificate =
            issuer.toASN1Structure().getToBeSigned();
        VerificationKeyIndicator vki = toBeSignedCertificate.getVerifyKeyIndicator();

        if (vki.getVerificationKeyIndicator() instanceof PublicVerificationKey)
        {
            PublicVerificationKey pvi = PublicVerificationKey.getInstance(vki.getVerificationKeyIndicator());
            initForPvi(pvi, helper);
        }
        else
        {
            throw new IllegalArgumentException("not public verification key");
        }
    }

    private JcaITSContentVerifierProvider(ITSPublicVerificationKey pvi, JcaJceHelper helper)
    {
        this.issuer = null;
        this.parentData = null;
        this.helper = helper;

        initForPvi(pvi.toASN1Structure(), helper);
    }

    private void initForPvi(PublicVerificationKey pvi, JcaJceHelper helper)
    {
        sigChoice = pvi.getChoice();
        switch (pvi.getChoice())
        {
        case PublicVerificationKey.ecdsaNistP256:
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
            break;
        case PublicVerificationKey.ecdsaBrainpoolP256r1:
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
            break;
        case PublicVerificationKey.ecdsaBrainpoolP384r1:
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
            break;
        default:
            throw new IllegalArgumentException("unknown key type");
        }

        pubParams = (ECPublicKey)new JcaITSPublicVerificationKey(pvi, helper).getKey();
    }

    public boolean hasAssociatedCertificate()
    {
        return issuer != null;
    }

    public ITSCertificate getAssociatedCertificate()
    {
        return issuer;
    }


    public ContentVerifier get(int verifierAlgorithmIdentifier)
        throws OperatorCreationException
    {
        if (sigChoice != verifierAlgorithmIdentifier)
        {
            throw new OperatorCreationException("wrong verifier for algorithm: " + verifierAlgorithmIdentifier);
        }

        DigestCalculatorProvider digestCalculatorProvider;

        try
        {
            JcaDigestCalculatorProviderBuilder bld = new JcaDigestCalculatorProviderBuilder().setHelper(helper);
            digestCalculatorProvider = bld.build();
        }
        catch (Exception ex)
        {
            throw new IllegalStateException(ex.getMessage(), ex);
        }

        final DigestCalculator calculator = digestCalculatorProvider.get(digestAlgo);
        try
        {
            final OutputStream os = calculator.getOutputStream();
            if (parentData != null)
            {
                os.write(parentData, 0, parentData.length);
            }
            final byte[] parentDigest = calculator.getDigest();

            final byte[] parentTBSDigest;

            if (issuer != null && issuer.getIssuer().isSelf())
            {
                byte[] enc = OEREncoder.toByteArray(issuer.toASN1Structure().getToBeSigned(), IEEE1609dot2.ToBeSignedCertificate.build());
                os.write(enc, 0, enc.length);
                parentTBSDigest = calculator.getDigest();
            }
            else
            {
                parentTBSDigest = null;
            }

            final Signature signature;
            switch (this.sigChoice)
            {
            case PublicVerificationKey.ecdsaNistP256:
            case PublicVerificationKey.ecdsaBrainpoolP256r1:
                signature = helper.createSignature("SHA256withECDSA");
                break;
            case PublicVerificationKey.ecdsaBrainpoolP384r1:
                signature = helper.createSignature("SHA384withECDSA");
                break;
            default:
                throw new IllegalArgumentException("choice " + this.sigChoice + " not supported");
            }

            return new ContentVerifier()
            {

                public AlgorithmIdentifier getAlgorithmIdentifier()
                {
                    return null;
                }


                public OutputStream getOutputStream()
                {
                    return os;
                }

                public boolean verify(byte[] expected)
                {
                    byte[] clientCertDigest = calculator.getDigest();
                    try
                    {
                        signature.initVerify(pubParams);
                        signature.update(clientCertDigest);

                        if (parentTBSDigest != null && Arrays.areEqual(clientCertDigest, parentTBSDigest))
                        {
                            byte[] empty = calculator.getDigest();
                            signature.update(empty);
                        }
                        else
                        {
                            signature.update(parentDigest);
                        }

                        return signature.verify(expected);
                    }
                    catch (Exception ex)
                    {
                        throw new RuntimeException(ex.getMessage(), ex);
                    }

                }
            };
        }
        catch (Exception ex)
        {
            throw new IllegalStateException(ex.getMessage(), ex);
        }
    }
}
