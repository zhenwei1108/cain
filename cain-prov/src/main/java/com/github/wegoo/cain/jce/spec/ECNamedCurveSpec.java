package com.github.wegoo.cain.jce.spec;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import com.github.wegoo.cain.jcajce.provider.asymmetric.util.EC5Util;
import com.github.wegoo.cain.math.ec.ECAlgorithms;
import com.github.wegoo.cain.math.ec.ECCurve;
import com.github.wegoo.cain.math.field.FiniteField;
import com.github.wegoo.cain.math.field.Polynomial;
import com.github.wegoo.cain.math.field.PolynomialExtensionField;
import com.github.wegoo.cain.util.Arrays;

/**
 * specification signifying that the curve parameters can also be
 * referred to by name.
 */
public class ECNamedCurveSpec
    extends java.security.spec.ECParameterSpec
{
    private String  name;

    private static EllipticCurve convertCurve(
        ECCurve  curve,
        byte[]   seed)
    {
        ECField field = convertField(curve.getField());
        BigInteger a = curve.getA().toBigInteger(), b = curve.getB().toBigInteger();
        return new EllipticCurve(field, a, b, seed);
    }

    private static ECField convertField(FiniteField field)
    {
        if (ECAlgorithms.isFpField(field))
        {
            return new ECFieldFp(field.getCharacteristic());
        }
        else //if (ECAlgorithms.isF2mField(curveField))
        {
            Polynomial poly = ((PolynomialExtensionField)field).getMinimalPolynomial();
            int[] exponents = poly.getExponentsPresent();
            int[] ks = Arrays.reverseInPlace(Arrays.copyOfRange(exponents, 1, exponents.length - 1));
            return new ECFieldF2m(poly.getDegree(), ks);
        }
    }

    public ECNamedCurveSpec(
        String                              name,
        ECCurve                             curve,
        com.github.wegoo.cain.math.ec.ECPoint    g,
        BigInteger                          n)
    {
        super(convertCurve(curve, null), EC5Util.convertPoint(g), n, 1);

        this.name = name;
    }

    public ECNamedCurveSpec(
        String          name,
        EllipticCurve   curve,
        ECPoint         g,
        BigInteger      n)
    {
        super(curve, g, n, 1);

        this.name = name;
    }
    
    public ECNamedCurveSpec(
        String                              name,
        ECCurve                             curve,
        com.github.wegoo.cain.math.ec.ECPoint    g,
        BigInteger                          n,
        BigInteger                          h)
    {
        super(convertCurve(curve, null), EC5Util.convertPoint(g), n, h.intValue());

        this.name = name;
    }

    public ECNamedCurveSpec(
        String          name,
        EllipticCurve   curve,
        ECPoint         g,
        BigInteger      n,
        BigInteger      h)
    {
        super(curve, g, n, h.intValue());

        this.name = name;
    }
    
    public ECNamedCurveSpec(
        String                              name,
        ECCurve                             curve,
        com.github.wegoo.cain.math.ec.ECPoint    g,
        BigInteger                          n,
        BigInteger                          h,
        byte[]                              seed)
    {
        super(convertCurve(curve, seed), EC5Util.convertPoint(g), n, h.intValue());

        this.name = name;
    }

    /**
     * return the name of the curve the EC domain parameters belong to.
     */
    public String getName()
    {
        return name;
    }
}
