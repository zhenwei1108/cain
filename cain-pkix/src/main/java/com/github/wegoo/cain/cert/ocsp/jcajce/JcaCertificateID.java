package com.github.wegoo.cain.cert.ocsp.jcajce;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import com.github.wegoo.cain.cert.jcajce.JcaX509CertificateHolder;
import com.github.wegoo.cain.cert.ocsp.CertificateID;
import com.github.wegoo.cain.cert.ocsp.OCSPException;
import com.github.wegoo.cain.operator.DigestCalculator;

public class JcaCertificateID
    extends CertificateID
{
    public JcaCertificateID(DigestCalculator digestCalculator, X509Certificate issuerCert, BigInteger number)
        throws OCSPException, CertificateEncodingException
    {
        super(digestCalculator, new JcaX509CertificateHolder(issuerCert), number);
    }
}
