package com.github.wegoo.cain.cert.crmf.jcajce;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.cert.crmf.CRMFException;
import com.github.wegoo.cain.cert.crmf.PKMACValuesCalculator;
import com.github.wegoo.cain.jcajce.util.DefaultJcaJceHelper;
import com.github.wegoo.cain.jcajce.util.NamedJcaJceHelper;
import com.github.wegoo.cain.jcajce.util.ProviderJcaJceHelper;

public class JcePKMACValuesCalculator
    implements PKMACValuesCalculator
{
    private MessageDigest digest;
    private Mac           mac;
    private CRMFHelper    helper;

    public JcePKMACValuesCalculator()
    {
        this.helper = new CRMFHelper(new DefaultJcaJceHelper());
    }

    public JcePKMACValuesCalculator setProvider(Provider provider)
    {
        this.helper = new CRMFHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JcePKMACValuesCalculator setProvider(String providerName)
    {
        this.helper = new CRMFHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    public void setup(AlgorithmIdentifier digAlg, AlgorithmIdentifier macAlg)
        throws CRMFException
    {
        digest = helper.createDigest(digAlg.getAlgorithm());
        mac = helper.createMac(macAlg.getAlgorithm());
    }

    public byte[] calculateDigest(byte[] data)
    {
        return digest.digest(data);
    }

    public byte[] calculateMac(byte[] pwd, byte[] data)
        throws CRMFException
    {
        try
        {
            mac.init(new SecretKeySpec(pwd, mac.getAlgorithm()));

            return mac.doFinal(data);
        }
        catch (GeneralSecurityException e)
        {
            throw new CRMFException("failure in setup: " + e.getMessage(), e);
        }
    }
}
