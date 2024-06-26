package com.github.wegoo.cain.cms;

import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.cert.X509CertificateHolder;
import com.github.wegoo.cain.operator.ContentVerifier;
import com.github.wegoo.cain.operator.ContentVerifierProvider;
import com.github.wegoo.cain.operator.DigestCalculator;
import com.github.wegoo.cain.operator.DigestCalculatorProvider;
import com.github.wegoo.cain.operator.OperatorCreationException;
import com.github.wegoo.cain.operator.SignatureAlgorithmIdentifierFinder;

public class SignerInformationVerifier
{
    private ContentVerifierProvider verifierProvider;
    private DigestCalculatorProvider digestProvider;
    private SignatureAlgorithmIdentifierFinder sigAlgorithmFinder;
    private CMSSignatureAlgorithmNameGenerator sigNameGenerator;

    public SignerInformationVerifier(CMSSignatureAlgorithmNameGenerator sigNameGenerator, SignatureAlgorithmIdentifierFinder sigAlgorithmFinder, ContentVerifierProvider verifierProvider, DigestCalculatorProvider digestProvider)
    {
        this.sigNameGenerator = sigNameGenerator;
        this.sigAlgorithmFinder = sigAlgorithmFinder;
        this.verifierProvider = verifierProvider;
        this.digestProvider = digestProvider;
    }

    public boolean hasAssociatedCertificate()
    {
        return verifierProvider.hasAssociatedCertificate();
    }

    public X509CertificateHolder getAssociatedCertificate()
    {
        return verifierProvider.getAssociatedCertificate();
    }

    public ContentVerifier getContentVerifier(AlgorithmIdentifier signingAlgorithm, AlgorithmIdentifier digestAlgorithm)
        throws OperatorCreationException
    {
        String              signatureName = sigNameGenerator.getSignatureName(digestAlgorithm, signingAlgorithm);
        AlgorithmIdentifier baseAlgID = sigAlgorithmFinder.find(signatureName);

        return verifierProvider.get(new AlgorithmIdentifier(baseAlgID.getAlgorithm(), signingAlgorithm.getParameters()));
    }

    public DigestCalculator getDigestCalculator(AlgorithmIdentifier algorithmIdentifier)
        throws OperatorCreationException
    {
        return digestProvider.get(algorithmIdentifier);
    }
}
