package com.github.wegoo.cain.cert.crmf;

import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;

public interface PKMACValuesCalculator
{
    void setup(AlgorithmIdentifier digestAlg, AlgorithmIdentifier macAlg)
        throws CRMFException;

    byte[] calculateDigest(byte[] data)
        throws CRMFException;

    byte[] calculateMac(byte[] pwd, byte[] data)
        throws CRMFException;
}
