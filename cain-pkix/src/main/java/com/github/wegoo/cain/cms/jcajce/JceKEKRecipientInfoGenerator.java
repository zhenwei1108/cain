package com.github.wegoo.cain.cms.jcajce;

import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import com.github.wegoo.cain.asn1.cms.KEKIdentifier;
import com.github.wegoo.cain.cms.KEKRecipientInfoGenerator;
import com.github.wegoo.cain.operator.jcajce.JceSymmetricKeyWrapper;

public class JceKEKRecipientInfoGenerator
    extends KEKRecipientInfoGenerator
{
    public JceKEKRecipientInfoGenerator(KEKIdentifier kekIdentifier, SecretKey keyEncryptionKey)
    {
        super(kekIdentifier, new JceSymmetricKeyWrapper(keyEncryptionKey));
    }

    public JceKEKRecipientInfoGenerator(byte[] keyIdentifier, SecretKey keyEncryptionKey)
    {
        this(new KEKIdentifier(keyIdentifier, null, null), keyEncryptionKey);
    }

    public JceKEKRecipientInfoGenerator setProvider(Provider provider)
    {
        ((JceSymmetricKeyWrapper)this.wrapper).setProvider(provider);

        return this;
    }

    public JceKEKRecipientInfoGenerator setProvider(String providerName)
    {
        ((JceSymmetricKeyWrapper)this.wrapper).setProvider(providerName);

        return this;
    }

    public JceKEKRecipientInfoGenerator setSecureRandom(SecureRandom random)
    {
        ((JceSymmetricKeyWrapper)this.wrapper).setSecureRandom(random);

        return this;
    }
}
