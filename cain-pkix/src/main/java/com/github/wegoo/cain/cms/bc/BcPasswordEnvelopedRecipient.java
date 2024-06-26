package com.github.wegoo.cain.cms.bc;

import java.io.InputStream;

import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.cms.CMSException;
import com.github.wegoo.cain.cms.RecipientOperator;
import com.github.wegoo.cain.crypto.BufferedBlockCipher;
import com.github.wegoo.cain.crypto.StreamCipher;
import com.github.wegoo.cain.crypto.io.CipherInputStream;
import com.github.wegoo.cain.crypto.params.KeyParameter;
import com.github.wegoo.cain.operator.InputDecryptor;

public class BcPasswordEnvelopedRecipient
    extends BcPasswordRecipient
{
    public BcPasswordEnvelopedRecipient(char[] password)
    {
        super(password);
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, final AlgorithmIdentifier contentEncryptionAlgorithm, byte[] derivedKey, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        KeyParameter secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, derivedKey, encryptedContentEncryptionKey);

        final Object dataCipher = EnvelopedDataHelper.createContentCipher(false, secretKey, contentEncryptionAlgorithm);

        return new RecipientOperator(new InputDecryptor()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return contentEncryptionAlgorithm;
            }

            public InputStream getInputStream(InputStream dataOut)
            {
                if (dataCipher instanceof BufferedBlockCipher)
                {
                    return new CipherInputStream(dataOut, (BufferedBlockCipher)dataCipher);
                }
                else
                {
                    return new CipherInputStream(dataOut, (StreamCipher)dataCipher);
                }
            }
        });
    }
}
