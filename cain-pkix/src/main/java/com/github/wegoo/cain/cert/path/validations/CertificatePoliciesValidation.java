package com.github.wegoo.cain.cert.path.validations;

import java.math.BigInteger;

import com.github.wegoo.cain.asn1.ASN1Integer;
import com.github.wegoo.cain.asn1.x509.Extension;
import com.github.wegoo.cain.asn1.x509.PolicyConstraints;
import com.github.wegoo.cain.cert.X509CertificateHolder;
import com.github.wegoo.cain.cert.path.CertPathValidation;
import com.github.wegoo.cain.cert.path.CertPathValidationContext;
import com.github.wegoo.cain.cert.path.CertPathValidationException;
import com.github.wegoo.cain.util.Memoable;

public class CertificatePoliciesValidation
    implements CertPathValidation
{
    private int              explicitPolicy;
    private int              policyMapping;
    private int              inhibitAnyPolicy;

    CertificatePoliciesValidation(int pathLength)
    {
        this(pathLength, false, false, false);
    }

    CertificatePoliciesValidation(int pathLength, boolean isExplicitPolicyRequired, boolean isAnyPolicyInhibited, boolean isPolicyMappingInhibited)
    {
        //
        // (d)
        //

        if (isExplicitPolicyRequired)
        {
            explicitPolicy = 0;
        }
        else
        {
            explicitPolicy = pathLength + 1;
        }

        //
        // (e)
        //
        if (isAnyPolicyInhibited)
        {
            inhibitAnyPolicy = 0;
        }
        else
        {
            inhibitAnyPolicy = pathLength + 1;
        }

        //
        // (f)
        //
        if (isPolicyMappingInhibited)
        {
            policyMapping = 0;
        }
        else
        {
            policyMapping = pathLength + 1;
        }
    }

    public void validate(CertPathValidationContext context, X509CertificateHolder certificate)
        throws CertPathValidationException
    {
        context.addHandledExtension(Extension.policyConstraints);
        context.addHandledExtension(Extension.inhibitAnyPolicy);

        if (!context.isEndEntity())
        {
            if (!ValidationUtils.isSelfIssued(certificate))
            {
                 //
                // H (1), (2), (3)
                //
                explicitPolicy = countDown(explicitPolicy);
                policyMapping = countDown(policyMapping);
                inhibitAnyPolicy = countDown(inhibitAnyPolicy);

                //
                // I (1), (2)
                //
                PolicyConstraints policyConstraints = PolicyConstraints.fromExtensions(certificate.getExtensions());

                if (policyConstraints != null)
                {
                    BigInteger requireExplicitPolicyMapping = policyConstraints.getRequireExplicitPolicyMapping();
                    if (requireExplicitPolicyMapping != null)
                    {
                        if (requireExplicitPolicyMapping.intValue() < explicitPolicy)
                        {
                            explicitPolicy = requireExplicitPolicyMapping.intValue();
                        }
                    }

                    BigInteger inhibitPolicyMapping = policyConstraints.getInhibitPolicyMapping();
                    if (inhibitPolicyMapping != null)
                    {
                        if (inhibitPolicyMapping.intValue() < policyMapping)
                        {
                            policyMapping = inhibitPolicyMapping.intValue();
                        }
                    }
                }

                //
                // J
                //
                Extension ext = certificate.getExtension(Extension.inhibitAnyPolicy);

                if (ext != null)
                {
                    int extValue = ASN1Integer.getInstance(ext.getParsedValue()).intValueExact();

                    if (extValue < inhibitAnyPolicy)
                    {
                        inhibitAnyPolicy = extValue;
                    }
                }
            }
        }
    }

    private int countDown(int policyCounter)
    {
        if (policyCounter != 0)
        {
            return policyCounter - 1;
        }

        return 0;
    }

    public Memoable copy()
    {
        CertificatePoliciesValidation v = new CertificatePoliciesValidation(0);

        v.explicitPolicy = this.explicitPolicy;
        v.policyMapping = this.policyMapping;
        v.inhibitAnyPolicy = this.inhibitAnyPolicy;

        return v;
    }

    public void reset(Memoable other)
    {
        CertificatePoliciesValidation v = (CertificatePoliciesValidation) other;

        this.explicitPolicy = v.explicitPolicy;
        this.policyMapping = v.policyMapping;
        this.inhibitAnyPolicy = v.inhibitAnyPolicy;
    }
}
