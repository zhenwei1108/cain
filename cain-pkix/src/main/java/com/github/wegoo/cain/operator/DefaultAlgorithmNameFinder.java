package com.github.wegoo.cain.operator;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.github.wegoo.cain.asn1.ASN1ObjectIdentifier;
import com.github.wegoo.cain.asn1.bc.BCObjectIdentifiers;
import com.github.wegoo.cain.asn1.bsi.BSIObjectIdentifiers;
import com.github.wegoo.cain.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.github.wegoo.cain.asn1.eac.EACObjectIdentifiers;
import com.github.wegoo.cain.asn1.gnu.GNUObjectIdentifiers;
import com.github.wegoo.cain.asn1.kisa.KISAObjectIdentifiers;
import com.github.wegoo.cain.asn1.misc.MiscObjectIdentifiers;
import com.github.wegoo.cain.asn1.nist.NISTObjectIdentifiers;
import com.github.wegoo.cain.asn1.ntt.NTTObjectIdentifiers;
import com.github.wegoo.cain.asn1.oiw.OIWObjectIdentifiers;
import com.github.wegoo.cain.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.wegoo.cain.asn1.rosstandart.RosstandartObjectIdentifiers;
import com.github.wegoo.cain.asn1.teletrust.TeleTrusTObjectIdentifiers;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.asn1.x9.X9ObjectIdentifiers;

public class DefaultAlgorithmNameFinder
    implements AlgorithmNameFinder
{
    private final static Map algorithms = new HashMap();

    static
    {
        algorithms.put(BSIObjectIdentifiers.ecdsa_plain_RIPEMD160, "RIPEMD160WITHPLAIN-ECDSA");
        algorithms.put(BSIObjectIdentifiers.ecdsa_plain_SHA1, "SHA1WITHPLAIN-ECDSA");
        algorithms.put(BSIObjectIdentifiers.ecdsa_plain_SHA224, "SHA224WITHPLAIN-ECDSA");
        algorithms.put(BSIObjectIdentifiers.ecdsa_plain_SHA256, "SHA256WITHPLAIN-ECDSA");
        algorithms.put(BSIObjectIdentifiers.ecdsa_plain_SHA384, "SHA384WITHPLAIN-ECDSA");
        algorithms.put(BSIObjectIdentifiers.ecdsa_plain_SHA512, "SHA512WITHPLAIN-ECDSA");
        algorithms.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, "GOST3411WITHECGOST3410-2001");
        algorithms.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3411WITHGOST3410-94");
        algorithms.put(CryptoProObjectIdentifiers.gostR3411, "GOST3411");
        algorithms.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, "GOST3411WITHECGOST3410-2012-256");
        algorithms.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, "GOST3411WITHECGOST3410-2012-512");
        algorithms.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_1, "SHA1WITHCVC-ECDSA");
        algorithms.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_224, "SHA224WITHCVC-ECDSA");
        algorithms.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_256, "SHA256WITHCVC-ECDSA");
        algorithms.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_384, "SHA384WITHCVC-ECDSA");
        algorithms.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_512, "SHA512WITHCVC-ECDSA");
        algorithms.put(BCObjectIdentifiers.falcon_512, "FALCON");
        algorithms.put(BCObjectIdentifiers.falcon_1024, "FALCON");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_shake_128s_r3, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_shake_128f_r3, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_haraka_128s_r3, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_haraka_128f_r3, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_shake_192s_r3, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_shake_192f_r3, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_haraka_192s_r3, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_haraka_192f_r3, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_shake_256s_r3, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_shake_256f_r3, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_haraka_256s_r3, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_haraka_256f_r3, "SPHINCS+");

        algorithms.put(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3_simple, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3_simple, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_shake_128s_r3_simple, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_shake_128f_r3_simple, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_haraka_128s_r3_simple, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_haraka_128f_r3_simple, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3_simple, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3_simple, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_shake_192s_r3_simple, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_shake_192f_r3_simple, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_haraka_192s_r3_simple, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_haraka_192f_r3_simple, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3_simple, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3_simple, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_shake_256s_r3_simple, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_shake_256f_r3_simple, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_haraka_256s_r3_simple, "SPHINCS+");
        algorithms.put(BCObjectIdentifiers.sphincsPlus_haraka_256f_r3_simple, "SPHINCS+");

        algorithms.put(NISTObjectIdentifiers.id_sha224, "SHA224");
        algorithms.put(NISTObjectIdentifiers.id_sha256, "SHA256");
        algorithms.put(NISTObjectIdentifiers.id_sha384, "SHA384");
        algorithms.put(NISTObjectIdentifiers.id_sha512, "SHA512");
        algorithms.put(NISTObjectIdentifiers.id_sha3_224, "SHA3-224");
        algorithms.put(NISTObjectIdentifiers.id_sha3_256, "SHA3-256");
        algorithms.put(NISTObjectIdentifiers.id_sha3_384, "SHA3-384");
        algorithms.put(NISTObjectIdentifiers.id_sha3_512, "SHA3-512");
        algorithms.put(OIWObjectIdentifiers.dsaWithSHA1, "SHA1WITHDSA");
        algorithms.put(OIWObjectIdentifiers.elGamalAlgorithm, "ELGAMAL");
        algorithms.put(OIWObjectIdentifiers.idSHA1, "SHA1");
        algorithms.put(OIWObjectIdentifiers.md5WithRSA, "MD5WITHRSA");
        algorithms.put(OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");
        algorithms.put(PKCSObjectIdentifiers.id_RSAES_OAEP, "RSAOAEP");
        algorithms.put(PKCSObjectIdentifiers.id_RSASSA_PSS, "RSAPSS");
        algorithms.put(PKCSObjectIdentifiers.md2WithRSAEncryption, "MD2WITHRSA");
        algorithms.put(PKCSObjectIdentifiers.md5, "MD5");
        algorithms.put(PKCSObjectIdentifiers.md5WithRSAEncryption, "MD5WITHRSA");
        algorithms.put(PKCSObjectIdentifiers.rsaEncryption, "RSA");
        algorithms.put(PKCSObjectIdentifiers.sha1WithRSAEncryption, "SHA1WITHRSA");
        algorithms.put(PKCSObjectIdentifiers.sha224WithRSAEncryption, "SHA224WITHRSA");
        algorithms.put(PKCSObjectIdentifiers.sha256WithRSAEncryption, "SHA256WITHRSA");
        algorithms.put(PKCSObjectIdentifiers.sha384WithRSAEncryption, "SHA384WITHRSA");
        algorithms.put(PKCSObjectIdentifiers.sha512WithRSAEncryption, "SHA512WITHRSA");
        algorithms.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224, "SHA3-224WITHRSA");
        algorithms.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256, "SHA3-256WITHRSA");
        algorithms.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384, "SHA3-384WITHRSA");
        algorithms.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512, "SHA3-512WITHRSA");
        algorithms.put(TeleTrusTObjectIdentifiers.ripemd128, "RIPEMD128");
        algorithms.put(TeleTrusTObjectIdentifiers.ripemd160, "RIPEMD160");
        algorithms.put(TeleTrusTObjectIdentifiers.ripemd256, "RIPEMD256");
        algorithms.put(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128, "RIPEMD128WITHRSA");
        algorithms.put(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160, "RIPEMD160WITHRSA");
        algorithms.put(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256, "RIPEMD256WITHRSA");
        algorithms.put(X9ObjectIdentifiers.ecdsa_with_SHA1, "ECDSAWITHSHA1");
        algorithms.put(X9ObjectIdentifiers.ecdsa_with_SHA224, "SHA224WITHECDSA");
        algorithms.put(X9ObjectIdentifiers.ecdsa_with_SHA256, "SHA256WITHECDSA");
        algorithms.put(X9ObjectIdentifiers.ecdsa_with_SHA384, "SHA384WITHECDSA");
        algorithms.put(X9ObjectIdentifiers.ecdsa_with_SHA512, "SHA512WITHECDSA");
        algorithms.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_224, "SHA3-224WITHECDSA");
        algorithms.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_256, "SHA3-256WITHECDSA");
        algorithms.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_384, "SHA3-384WITHECDSA");
        algorithms.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_512, "SHA3-512WITHECDSA");
        algorithms.put(X9ObjectIdentifiers.id_dsa_with_sha1, "SHA1WITHDSA");
        algorithms.put(NISTObjectIdentifiers.dsa_with_sha224, "SHA224WITHDSA");
        algorithms.put(NISTObjectIdentifiers.dsa_with_sha256, "SHA256WITHDSA");
        algorithms.put(NISTObjectIdentifiers.dsa_with_sha384, "SHA384WITHDSA");
        algorithms.put(NISTObjectIdentifiers.dsa_with_sha512, "SHA512WITHDSA");
        algorithms.put(NISTObjectIdentifiers.id_dsa_with_sha3_224, "SHA3-224WITHDSA");
        algorithms.put(NISTObjectIdentifiers.id_dsa_with_sha3_256, "SHA3-256WITHDSA");
        algorithms.put(NISTObjectIdentifiers.id_dsa_with_sha3_384, "SHA3-384WITHDSA");
        algorithms.put(NISTObjectIdentifiers.id_dsa_with_sha3_512, "SHA3-512WITHDSA");
        algorithms.put(GNUObjectIdentifiers.Tiger_192, "Tiger");

        algorithms.put(PKCSObjectIdentifiers.RC2_CBC, "RC2/CBC");
        algorithms.put(PKCSObjectIdentifiers.des_EDE3_CBC, "DESEDE-3KEY/CBC");
        algorithms.put(NISTObjectIdentifiers.id_aes128_ECB, "AES-128/ECB");
        algorithms.put(NISTObjectIdentifiers.id_aes192_ECB, "AES-192/ECB");
        algorithms.put(NISTObjectIdentifiers.id_aes256_ECB, "AES-256/ECB");
        algorithms.put(NISTObjectIdentifiers.id_aes128_CBC, "AES-128/CBC");
        algorithms.put(NISTObjectIdentifiers.id_aes192_CBC, "AES-192/CBC");
        algorithms.put(NISTObjectIdentifiers.id_aes256_CBC, "AES-256/CBC");
        algorithms.put(NISTObjectIdentifiers.id_aes128_CFB, "AES-128/CFB");
        algorithms.put(NISTObjectIdentifiers.id_aes192_CFB, "AES-192/CFB");
        algorithms.put(NISTObjectIdentifiers.id_aes256_CFB, "AES-256/CFB");
        algorithms.put(NISTObjectIdentifiers.id_aes128_OFB, "AES-128/OFB");
        algorithms.put(NISTObjectIdentifiers.id_aes192_OFB, "AES-192/OFB");
        algorithms.put(NISTObjectIdentifiers.id_aes256_OFB, "AES-256/OFB");
        algorithms.put(NTTObjectIdentifiers.id_camellia128_cbc, "CAMELLIA-128/CBC");
        algorithms.put(NTTObjectIdentifiers.id_camellia192_cbc, "CAMELLIA-192/CBC");
        algorithms.put(NTTObjectIdentifiers.id_camellia256_cbc, "CAMELLIA-256/CBC");
        algorithms.put(KISAObjectIdentifiers.id_seedCBC, "SEED/CBC");
        algorithms.put(MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC, "IDEA/CBC");
        algorithms.put(MiscObjectIdentifiers.cast5CBC, "CAST5/CBC");
        algorithms.put(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_ECB, "Blowfish/ECB");
        algorithms.put(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CBC, "Blowfish/CBC");
        algorithms.put(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CFB, "Blowfish/CFB");
        algorithms.put(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_OFB, "Blowfish/OFB");
        algorithms.put(GNUObjectIdentifiers.Serpent_128_ECB, "Serpent-128/ECB");
        algorithms.put(GNUObjectIdentifiers.Serpent_128_CBC, "Serpent-128/CBC");
        algorithms.put(GNUObjectIdentifiers.Serpent_128_CFB, "Serpent-128/CFB");
        algorithms.put(GNUObjectIdentifiers.Serpent_128_OFB, "Serpent-128/OFB");
        algorithms.put(GNUObjectIdentifiers.Serpent_192_ECB, "Serpent-192/ECB");
        algorithms.put(GNUObjectIdentifiers.Serpent_192_CBC, "Serpent-192/CBC");
        algorithms.put(GNUObjectIdentifiers.Serpent_192_CFB, "Serpent-192/CFB");
        algorithms.put(GNUObjectIdentifiers.Serpent_192_OFB, "Serpent-192/OFB");
        algorithms.put(GNUObjectIdentifiers.Serpent_256_ECB, "Serpent-256/ECB");
        algorithms.put(GNUObjectIdentifiers.Serpent_256_CBC, "Serpent-256/CBC");
        algorithms.put(GNUObjectIdentifiers.Serpent_256_CFB, "Serpent-256/CFB");
        algorithms.put(GNUObjectIdentifiers.Serpent_256_OFB, "Serpent-256/OFB");
        algorithms.put(MiscObjectIdentifiers.id_blake2b160, "BLAKE2b-160");
        algorithms.put(MiscObjectIdentifiers.id_blake2b256, "BLAKE2b-256");
        algorithms.put(MiscObjectIdentifiers.id_blake2b384, "BLAKE2b-384");
        algorithms.put(MiscObjectIdentifiers.id_blake2b512, "BLAKE2b-512");
        algorithms.put(MiscObjectIdentifiers.id_blake2s128, "BLAKE2s-128");
        algorithms.put(MiscObjectIdentifiers.id_blake2s160, "BLAKE2s-160");
        algorithms.put(MiscObjectIdentifiers.id_blake2s224, "BLAKE2s-224");
        algorithms.put(MiscObjectIdentifiers.id_blake2s256, "BLAKE2s-256");
        algorithms.put(MiscObjectIdentifiers.blake3_256, "BLAKE3-256");
    }

    public boolean hasAlgorithmName(ASN1ObjectIdentifier objectIdentifier)
    {
        return algorithms.containsKey(objectIdentifier);
    }

    public String getAlgorithmName(ASN1ObjectIdentifier objectIdentifier)
    {
        String name = (String)algorithms.get(objectIdentifier);

        return (name != null) ? name : objectIdentifier.getId();
    }

    public String getAlgorithmName(AlgorithmIdentifier algorithmIdentifier)
    {
        // TODO: take into account PSS/OAEP params
        return getAlgorithmName(algorithmIdentifier.getAlgorithm());
    }

    public Set<ASN1ObjectIdentifier> getOIDSet()
    {
        return algorithms.keySet();
    }
}
