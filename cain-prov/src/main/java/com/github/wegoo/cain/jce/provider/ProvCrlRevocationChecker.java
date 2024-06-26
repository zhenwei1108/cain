package com.github.wegoo.cain.jce.provider;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import com.github.wegoo.cain.jcajce.PKIXCertRevocationChecker;
import com.github.wegoo.cain.jcajce.PKIXCertRevocationCheckerParameters;
import com.github.wegoo.cain.jcajce.util.JcaJceHelper;

class ProvCrlRevocationChecker
    implements PKIXCertRevocationChecker
{
    private final JcaJceHelper helper;

    private PKIXCertRevocationCheckerParameters params;
    private Date currentDate = null;

    public ProvCrlRevocationChecker(JcaJceHelper helper)
    {
        this.helper = helper;
    }

    public void setParameter(String name, Object value)
    {

    }

    public void initialize(PKIXCertRevocationCheckerParameters params)
    {
        this.params = params;
        this.currentDate = new Date();
    }

    public void init(boolean forForward)
        throws CertPathValidatorException
    {
        if (forForward)
        {
            throw new CertPathValidatorException("forward checking not supported");
        }

        this.params = null;
        this.currentDate = new Date();
    }

    public void check(Certificate certificate)
        throws CertPathValidatorException
    {
        try
        {
            RFC3280CertPathUtilities.checkCRLs(params, params.getParamsPKIX(), currentDate, params.getValidDate(),
                (X509Certificate)certificate, params.getSigningCert(), params.getWorkingPublicKey(),
                params.getCertPath().getCertificates(), helper);
        }
        catch (AnnotatedException e)
        {
            Throwable cause = e;
            if (null != e.getCause())
            {
                cause = e.getCause();
            }
            throw new CertPathValidatorException(e.getMessage(), cause, params.getCertPath(), params.getIndex());
        }
    }
}
