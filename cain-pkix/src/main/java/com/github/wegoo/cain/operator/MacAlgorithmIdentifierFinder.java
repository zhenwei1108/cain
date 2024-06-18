package com.github.wegoo.cain.operator;

import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;

public interface MacAlgorithmIdentifierFinder
{
    /**
     * Find the algorithm identifier that matches with
     * the passed in digest name.
     *
     * @param macAlgName the name of the digest algorithm of interest.
     * @return an algorithm identifier for the MAC.
     */
    AlgorithmIdentifier find(String macAlgName);
}