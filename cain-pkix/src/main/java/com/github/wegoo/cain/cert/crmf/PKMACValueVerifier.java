package com.github.wegoo.cain.cert.crmf;

import java.io.IOException;
import java.io.OutputStream;

import com.github.wegoo.cain.asn1.ASN1Encoding;
import com.github.wegoo.cain.asn1.cmp.PBMParameter;
import com.github.wegoo.cain.asn1.crmf.PKMACValue;
import com.github.wegoo.cain.asn1.x509.SubjectPublicKeyInfo;
import com.github.wegoo.cain.operator.MacCalculator;
import com.github.wegoo.cain.util.Arrays;

class PKMACValueVerifier
{
    private final PKMACBuilder builder;

    public PKMACValueVerifier(PKMACBuilder builder)
    {
        this.builder = builder;
    }

    public boolean isValid(PKMACValue value, char[] password, SubjectPublicKeyInfo keyInfo)
        throws CRMFException
    {
        builder.setParameters(PBMParameter.getInstance(value.getAlgId().getParameters()));
        MacCalculator calculator = builder.build(password);

        OutputStream macOut = calculator.getOutputStream();

        try
        {
            macOut.write(keyInfo.getEncoded(ASN1Encoding.DER));

            macOut.close();
        }
        catch (IOException e)
        {
            throw new CRMFException("exception encoding mac input: " + e.getMessage(), e);
        }

        return Arrays.constantTimeAreEqual(calculator.getMac(), value.getValue().getOctets());
    }
}
