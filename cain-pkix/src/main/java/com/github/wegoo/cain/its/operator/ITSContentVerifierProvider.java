package com.github.wegoo.cain.its.operator;

import com.github.wegoo.cain.its.ITSCertificate;
import com.github.wegoo.cain.operator.ContentVerifier;
import com.github.wegoo.cain.operator.OperatorCreationException;

public interface ITSContentVerifierProvider
{
    /**
     * Return whether or not this verifier has a certificate associated with it.
     *
     * @return true if there is an associated certificate, false otherwise.
     */
    boolean hasAssociatedCertificate();

    /**
     * Return the associated certificate if there is one.
     *
     * @return a holder containing the associated certificate if there is one, null if there is not.
     */
    ITSCertificate getAssociatedCertificate();

    /**
     * Return a ContentVerifier that matches the passed in algorithm identifier,
     *
     * @param signatureChoice the algorithm choice
     * @return a matching ContentVerifier
     * @throws OperatorCreationException if the required ContentVerifier cannot be created.
     */
    ContentVerifier get(int signatureChoice)
        throws OperatorCreationException;
}
