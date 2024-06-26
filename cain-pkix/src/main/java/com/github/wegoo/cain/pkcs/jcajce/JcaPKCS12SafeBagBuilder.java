package com.github.wegoo.cain.pkcs.jcajce;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import com.github.wegoo.cain.asn1.pkcs.PrivateKeyInfo;
import com.github.wegoo.cain.asn1.x509.Certificate;
import com.github.wegoo.cain.operator.OutputEncryptor;
import com.github.wegoo.cain.pkcs.PKCS12SafeBagBuilder;
import com.github.wegoo.cain.pkcs.PKCSIOException;

public class JcaPKCS12SafeBagBuilder
    extends PKCS12SafeBagBuilder
{
    public JcaPKCS12SafeBagBuilder(X509Certificate certificate)
        throws IOException
    {
        super(convertCert(certificate));
    }

    private static Certificate convertCert(X509Certificate certificate)
        throws IOException
    {
        try
        {
            return Certificate.getInstance(certificate.getEncoded());
        }
        catch (CertificateEncodingException e)
        {
            throw new PKCSIOException("cannot encode certificate: " + e.getMessage(), e);
        }
    }

    public JcaPKCS12SafeBagBuilder(PrivateKey privateKey, OutputEncryptor encryptor)
    {
        super(PrivateKeyInfo.getInstance(privateKey.getEncoded()), encryptor);
    }

    public JcaPKCS12SafeBagBuilder(PrivateKey privateKey)
    {
        super(PrivateKeyInfo.getInstance(privateKey.getEncoded()));
    }
}
