package com.github.wegoo.cain.cms.bc;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.github.wegoo.cain.asn1.ASN1ObjectIdentifier;
import com.github.wegoo.cain.asn1.nist.NISTObjectIdentifiers;
import com.github.wegoo.cain.asn1.oiw.OIWObjectIdentifiers;
import com.github.wegoo.cain.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.cms.CMSAlgorithm;
import com.github.wegoo.cain.cms.CMSException;
import com.github.wegoo.cain.crypto.CipherKeyGenerator;
import com.github.wegoo.cain.crypto.CipherParameters;
import com.github.wegoo.cain.crypto.ExtendedDigest;
import com.github.wegoo.cain.crypto.Wrapper;
import com.github.wegoo.cain.crypto.digests.SHA1Digest;
import com.github.wegoo.cain.crypto.digests.SHA224Digest;
import com.github.wegoo.cain.crypto.digests.SHA256Digest;
import com.github.wegoo.cain.crypto.digests.SHA384Digest;
import com.github.wegoo.cain.crypto.digests.SHA512Digest;
import com.github.wegoo.cain.crypto.engines.AESEngine;
import com.github.wegoo.cain.crypto.engines.DESEngine;
import com.github.wegoo.cain.crypto.engines.DESedeEngine;
import com.github.wegoo.cain.crypto.engines.RC2Engine;
import com.github.wegoo.cain.crypto.engines.RFC3211WrapEngine;
import com.github.wegoo.cain.crypto.params.KeyParameter;
import com.github.wegoo.cain.crypto.util.AlgorithmIdentifierFactory;
import com.github.wegoo.cain.crypto.util.CipherFactory;
import com.github.wegoo.cain.crypto.util.CipherKeyGeneratorFactory;
import com.github.wegoo.cain.operator.OperatorCreationException;
import com.github.wegoo.cain.operator.bc.BcDigestProvider;

class EnvelopedDataHelper
{
    protected static final Map BASE_CIPHER_NAMES = new HashMap();
    protected static final Map MAC_ALG_NAMES = new HashMap();

    private static final Set authEnvelopedAlgorithms = new HashSet();
    private static final Map prfs = createTable();

    private static Map createTable()
    {
        Map table = new HashMap();

        table.put(PKCSObjectIdentifiers.id_hmacWithSHA1, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA1Digest();
            }
        });
        table.put(PKCSObjectIdentifiers.id_hmacWithSHA224, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA224Digest();
            }
        });
        table.put(PKCSObjectIdentifiers.id_hmacWithSHA256, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return SHA256Digest.newInstance();
            }
        });
        table.put(PKCSObjectIdentifiers.id_hmacWithSHA384, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA384Digest();
            }
        });
        table.put(PKCSObjectIdentifiers.id_hmacWithSHA512, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA512Digest();
            }
        });

        return Collections.unmodifiableMap(table);
    }

    static
    {
        BASE_CIPHER_NAMES.put(CMSAlgorithm.DES_EDE3_CBC, "DESEDE");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.AES128_CBC, "AES");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.AES192_CBC, "AES");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.AES256_CBC, "AES");

        MAC_ALG_NAMES.put(CMSAlgorithm.DES_EDE3_CBC, "DESEDEMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.AES128_CBC, "AESMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.AES192_CBC, "AESMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.AES256_CBC, "AESMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.RC2_CBC, "RC2Mac");

        authEnvelopedAlgorithms.add(NISTObjectIdentifiers.id_aes128_GCM);
        authEnvelopedAlgorithms.add(NISTObjectIdentifiers.id_aes192_GCM);
        authEnvelopedAlgorithms.add(NISTObjectIdentifiers.id_aes256_GCM);
        authEnvelopedAlgorithms.add(NISTObjectIdentifiers.id_aes128_CCM);
        authEnvelopedAlgorithms.add(NISTObjectIdentifiers.id_aes192_CCM);
        authEnvelopedAlgorithms.add(NISTObjectIdentifiers.id_aes256_CCM);
    }

    EnvelopedDataHelper()
    {
    }

    static ExtendedDigest getPRF(AlgorithmIdentifier algID)
        throws OperatorCreationException
    {
        return ((BcDigestProvider)prfs.get(algID.getAlgorithm())).get(null);
    }

    static Wrapper createRFC3211Wrapper(ASN1ObjectIdentifier algorithm)
        throws CMSException
    {
        if (NISTObjectIdentifiers.id_aes128_CBC.equals(algorithm)
            || NISTObjectIdentifiers.id_aes192_CBC.equals(algorithm)
            || NISTObjectIdentifiers.id_aes256_CBC.equals(algorithm))
        {
            return new RFC3211WrapEngine(AESEngine.newInstance());
        }
        else if (PKCSObjectIdentifiers.des_EDE3_CBC.equals(algorithm))
        {
            return new RFC3211WrapEngine(new DESedeEngine());
        }
        else if (OIWObjectIdentifiers.desCBC.equals(algorithm))
        {
            return new RFC3211WrapEngine(new DESEngine());
        }
        else if (PKCSObjectIdentifiers.RC2_CBC.equals(algorithm))
        {
            return new RFC3211WrapEngine(new RC2Engine());
        }
        else
        {
            throw new CMSException("cannot recognise wrapper: " + algorithm);
        }
    }

    static Object createContentCipher(boolean forEncryption, CipherParameters encKey, AlgorithmIdentifier encryptionAlgID)
        throws CMSException
    {
        try
        {
            return CipherFactory.createContentCipher(forEncryption, encKey, encryptionAlgID);
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException(e.getMessage(), e);
        }
    }

    AlgorithmIdentifier generateEncryptionAlgID(ASN1ObjectIdentifier encryptionOID, KeyParameter encKey, SecureRandom random)
        throws CMSException
    {
        try
        {
            return AlgorithmIdentifierFactory.generateEncryptionAlgID(encryptionOID, encKey.getKey().length * 8, random);
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException(e.getMessage(), e);
        }
    }

    // TODO: make use of keySize parameter.
    CipherKeyGenerator createKeyGenerator(ASN1ObjectIdentifier algorithm, int keySize, SecureRandom random)
        throws CMSException
    {
        try
        {
            return CipherKeyGeneratorFactory.createKeyGenerator(algorithm, random);
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException(e.getMessage(), e);
        }
    }

    boolean isAuthEnveloped(ASN1ObjectIdentifier algorithm)
    {
        return authEnvelopedAlgorithms.contains(algorithm);
    }
}
