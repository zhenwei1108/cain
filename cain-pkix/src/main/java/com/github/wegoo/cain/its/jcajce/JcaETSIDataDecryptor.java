package com.github.wegoo.cain.its.jcajce;

import java.security.PrivateKey;
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import com.github.wegoo.cain.its.operator.ETSIDataDecryptor;
import com.github.wegoo.cain.jcajce.spec.IESKEMParameterSpec;
import com.github.wegoo.cain.jcajce.util.JcaJceHelper;
import com.github.wegoo.cain.jcajce.util.NamedJcaJceHelper;
import com.github.wegoo.cain.jcajce.util.ProviderJcaJceHelper;
import com.github.wegoo.cain.util.Arrays;


public class JcaETSIDataDecryptor
    implements ETSIDataDecryptor
{
    private final PrivateKey privateKey;
    private final JcaJceHelper helper;
    private final byte[] recipientHash;

    private SecretKey secretKey = null;

    JcaETSIDataDecryptor(PrivateKey recipientInfo, byte[] recipientHash, JcaJceHelper provider)
    {
        this.privateKey = recipientInfo;
        this.helper = provider;
        this.recipientHash = recipientHash;
    }

    public byte[] decrypt(byte[] wrappedKey, byte[] content, byte[] nonce)
    {
        try
        {
            Cipher etsiKem = helper.createCipher("ETSIKEMwithSHA256");
            etsiKem.init(Cipher.UNWRAP_MODE, privateKey, new IESKEMParameterSpec(recipientHash));

            // [ephemeral public key][encrypted key][tag]
            secretKey = (SecretKey)etsiKem.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);

            Cipher ccm = helper.createCipher("CCM");
            ccm.init(Cipher.DECRYPT_MODE, secretKey, ClassUtil.getGCMSpec(nonce, 128));
            return ccm.doFinal(content);
        }
        catch (Exception gex)
        {
            throw new RuntimeException(gex.getMessage(), gex);
        }
    }

    public byte[] getKey()
    {
        if (secretKey == null)
        {
            throw new IllegalStateException("no secret key recovered");
        }

        return secretKey.getEncoded();
    }


    public static Builder builder(PrivateKey privateKey, byte[] recipientHash)
    {
        return new Builder(privateKey, recipientHash);
    }

    public static class Builder
    {
        private JcaJceHelper provider;
        private final byte[] recipientHash;
        private final PrivateKey key;

        public Builder(PrivateKey key, byte[] recipientHash)
        {
            this.key = key;
            this.recipientHash = Arrays.clone(recipientHash);
        }

        public Builder provider(Provider provider)
        {
            this.provider = new ProviderJcaJceHelper(provider);
            return this;
        }

        public Builder provider(String provider)
        {
            this.provider = new NamedJcaJceHelper(provider);
            return this;
        }

        public JcaETSIDataDecryptor build()
        {
            return new JcaETSIDataDecryptor(key, recipientHash, provider);
        }
    }


}
