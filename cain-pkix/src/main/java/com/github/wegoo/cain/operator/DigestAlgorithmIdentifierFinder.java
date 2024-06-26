package com.github.wegoo.cain.operator;

import com.github.wegoo.cain.asn1.ASN1ObjectIdentifier;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;

public interface DigestAlgorithmIdentifierFinder
{
    /**
     * Find the digest algorithm identifier that matches with
     * the passed in signature algorithm identifier.
     *
     * @param sigAlgId the signature algorithm of interest.
     * @return an algorithm identifier for the corresponding digest.
     */
    AlgorithmIdentifier find(AlgorithmIdentifier sigAlgId);

    /**
     * Find the algorithm identifier that matches with
     * the passed in digest OID.
     *
     * @param digestOid the OID of the digest algorithm of interest.
     * @return an algorithm identifier for the digest signature.
     */
    AlgorithmIdentifier find(ASN1ObjectIdentifier digestOid);

    /**
     * Find the algorithm identifier that matches with
     * the passed in digest name.
     *
     * @param digAlgName the name of the digest algorithm of interest.
     * @return an algorithm identifier for the digest signature.
     */
    AlgorithmIdentifier find(String digAlgName);
}