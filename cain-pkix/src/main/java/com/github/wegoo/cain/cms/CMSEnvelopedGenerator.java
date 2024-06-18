package com.github.wegoo.cain.cms;

import java.util.ArrayList;
import java.util.List;

import com.github.wegoo.cain.asn1.cms.OriginatorInfo;
import com.github.wegoo.cain.asn1.kisa.KISAObjectIdentifiers;
import com.github.wegoo.cain.asn1.misc.MiscObjectIdentifiers;
import com.github.wegoo.cain.asn1.nist.NISTObjectIdentifiers;
import com.github.wegoo.cain.asn1.ntt.NTTObjectIdentifiers;
import com.github.wegoo.cain.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.wegoo.cain.asn1.sec.SECObjectIdentifiers;
import com.github.wegoo.cain.asn1.x9.X9ObjectIdentifiers;

/**
 * General class for generating a CMS enveloped-data message.
 */
public class CMSEnvelopedGenerator
{
    public static final String  DES_EDE3_CBC    = PKCSObjectIdentifiers.des_EDE3_CBC.getId();
    public static final String  RC2_CBC         = PKCSObjectIdentifiers.RC2_CBC.getId();
    public static final String  IDEA_CBC        = MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC.getId();
    public static final String  CAST5_CBC       = MiscObjectIdentifiers.cast5CBC.getId();
    public static final String  AES128_CBC      = NISTObjectIdentifiers.id_aes128_CBC.getId();
    public static final String  AES192_CBC      = NISTObjectIdentifiers.id_aes192_CBC.getId();
    public static final String  AES256_CBC      = NISTObjectIdentifiers.id_aes256_CBC.getId();
    public static final String  CAMELLIA128_CBC = NTTObjectIdentifiers.id_camellia128_cbc.getId();
    public static final String  CAMELLIA192_CBC = NTTObjectIdentifiers.id_camellia192_cbc.getId();
    public static final String  CAMELLIA256_CBC = NTTObjectIdentifiers.id_camellia256_cbc.getId();
    public static final String  SEED_CBC        = KISAObjectIdentifiers.id_seedCBC.getId();

    public static final String  DES_EDE3_WRAP   = PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId();
    public static final String  AES128_WRAP     = NISTObjectIdentifiers.id_aes128_wrap.getId();
    public static final String  AES192_WRAP     = NISTObjectIdentifiers.id_aes192_wrap.getId();
    public static final String  AES256_WRAP     = NISTObjectIdentifiers.id_aes256_wrap.getId();
    public static final String  CAMELLIA128_WRAP = NTTObjectIdentifiers.id_camellia128_wrap.getId();
    public static final String  CAMELLIA192_WRAP = NTTObjectIdentifiers.id_camellia192_wrap.getId();
    public static final String  CAMELLIA256_WRAP = NTTObjectIdentifiers.id_camellia256_wrap.getId();
    public static final String  SEED_WRAP       = KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap.getId();

    public static final String  ECDH_SHA1KDF    = X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme.getId();
    public static final String  ECMQV_SHA1KDF   = X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme.getId();
    public static final String  ECMQV_SHA224KDF = SECObjectIdentifiers.mqvSinglePass_sha224kdf_scheme.getId();
    public static final String  ECMQV_SHA256KDF = SECObjectIdentifiers.mqvSinglePass_sha256kdf_scheme.getId();
    public static final String  ECMQV_SHA384KDF = SECObjectIdentifiers.mqvSinglePass_sha384kdf_scheme.getId();
    public static final String  ECMQV_SHA512KDF = SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme.getId();

    final List recipientInfoGenerators = new ArrayList();

    protected CMSAttributeTableGenerator unprotectedAttributeGenerator = null;

    protected OriginatorInfo originatorInfo;

    /**
     * base constructor
     */
    protected CMSEnvelopedGenerator()
    {
    }

    public void setUnprotectedAttributeGenerator(CMSAttributeTableGenerator unprotectedAttributeGenerator)
    {
        this.unprotectedAttributeGenerator = unprotectedAttributeGenerator;
    }

    public void setOriginatorInfo(OriginatorInformation originatorInfo)
    {
        this.originatorInfo = originatorInfo.toASN1Structure();
    }

    /**
     * Add a generator to produce the recipient info required.
     * 
     * @param recipientGenerator a generator of a recipient info object.
     */
    public void addRecipientInfoGenerator(RecipientInfoGenerator recipientGenerator)
    {
        recipientInfoGenerators.add(recipientGenerator);
    }
}
