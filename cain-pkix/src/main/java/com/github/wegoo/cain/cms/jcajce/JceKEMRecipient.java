package com.github.wegoo.cain.cms.jcajce;

import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import com.github.wegoo.cain.asn1.ASN1ObjectIdentifier;
import com.github.wegoo.cain.asn1.cms.KEMRecipientInfo;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.cms.CMSException;
import com.github.wegoo.cain.cms.KEMRecipient;
import com.github.wegoo.cain.operator.OperatorException;

public abstract class JceKEMRecipient
    implements KEMRecipient
{
    private PrivateKey recipientKey;

    protected EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
    protected EnvelopedDataHelper contentHelper = helper;
    protected Map extraMappings = new HashMap();
    protected boolean validateKeySize = false;
    protected boolean unwrappedKeyMustBeEncodable;

    public JceKEMRecipient(PrivateKey recipientKey)
    {
        this.recipientKey = CMSUtils.cleanPrivateKey(recipientKey);
    }

    /**
     * Set the provider to use for key recovery and content processing.
     *
     * @param provider provider to use.
     * @return this recipient.
     */
    public JceKEMRecipient setProvider(Provider provider)
    {
        this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));
        this.contentHelper = helper;

        return this;
    }

    /**
     * Set the provider to use for key recovery and content processing.
     *
     * @param providerName the name of the provider to use.
     * @return this recipient.
     */
    public JceKEMRecipient setProvider(String providerName)
    {
        this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));
        this.contentHelper = helper;

        return this;
    }

    /**
     * Internally algorithm ids are converted into cipher names using a lookup table. For some providers
     * the standard lookup table won't work. Use this method to establish a specific mapping from an
     * algorithm identifier to a specific algorithm.
     * <p>
     * For example:
     * <pre>
     *     unwrapper.setAlgorithmMapping(PKCSObjectIdentifiers.rsaEncryption, "RSA");
     * </pre>
     *
     * @param algorithm     OID of algorithm in recipient.
     * @param algorithmName JCE algorithm name to use.
     * @return the current Recipient.
     */
    public JceKEMRecipient setAlgorithmMapping(ASN1ObjectIdentifier algorithm, String algorithmName)
    {
        extraMappings.put(algorithm, algorithmName);

        return this;
    }

    /**
     * Set the provider to use for content processing.  If providerName is null a "no provider" search will be
     * used to satisfy getInstance calls.
     *
     * @param provider the provider to use.
     * @return this recipient.
     */
    public JceKEMRecipient setContentProvider(Provider provider)
    {
        this.contentHelper = CMSUtils.createContentHelper(provider);

        return this;
    }

    /**
     * Flag that unwrapping must produce a key that will return a meaningful value from a call to Key.getEncoded().
     * This is important if you are using a HSM for unwrapping and using a software based provider for
     * decrypting the content. Default value: false.
     *
     * @param unwrappedKeyMustBeEncodable true if getEncoded() should return key bytes, false if not necessary.
     * @return this recipient.
     */
    public JceKEMRecipient setMustProduceEncodableUnwrappedKey(boolean unwrappedKeyMustBeEncodable)
    {
        this.unwrappedKeyMustBeEncodable = unwrappedKeyMustBeEncodable;

        return this;
    }

    /**
     * Set the provider to use for content processing.  If providerName is null a "no provider" search will be
     * used to satisfy getInstance calls.
     *
     * @param providerName the name of the provider to use.
     * @return this recipient.
     */
    public JceKEMRecipient setContentProvider(String providerName)
    {
        this.contentHelper = CMSUtils.createContentHelper(providerName);

        return this;
    }

    /**
     * Set validation of retrieved key sizes against the algorithm parameters for the encrypted key where possible - default is off.
     * <p>
     * This setting will not have any affect if the encryption algorithm in the recipient does not specify a particular key size, or
     * if the unwrapper is a HSM and the byte encoding of the unwrapped secret key is not available.
     * </p>
     *
     * @param doValidate true if unwrapped key's should be validated against the content encryption algorithm, false otherwise.
     * @return this recipient.
     */
    public JceKEMRecipient setKeySizeValidation(boolean doValidate)
    {
        this.validateKeySize = doValidate;

        return this;
    }

    protected Key extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedEncryptionKey)
        throws CMSException
    {
        // TODO: note there is a move to change the type for KEMs from KeyTrans, expect this to change
        KEMRecipientInfo gktParams = KEMRecipientInfo.getInstance(keyEncryptionAlgorithm.getParameters());

        JceCMSKEMKeyUnwrapper unwrapper = (JceCMSKEMKeyUnwrapper)helper.createKEMUnwrapper(keyEncryptionAlgorithm, recipientKey); // TODO: .setMustProduceEncodableUnwrappedKey(unwrappedKeyMustBeEncodable);

        if (!extraMappings.isEmpty())
        {
            for (Iterator it = extraMappings.keySet().iterator(); it.hasNext(); )
            {
                ASN1ObjectIdentifier algorithm = (ASN1ObjectIdentifier)it.next();

                unwrapper.setAlgorithmMapping(algorithm, (String)extraMappings.get(algorithm));
            }
        }

        try
        {
            Key key = helper.getJceKey(encryptedKeyAlgorithm, unwrapper.generateUnwrappedKey(encryptedKeyAlgorithm, encryptedEncryptionKey));

            if (validateKeySize)
            {
                helper.keySizeCheck(encryptedKeyAlgorithm, key);
            }

            return key;
        }
        catch (OperatorException e)
        {
            throw new CMSException("exception unwrapping key: " + e.getMessage(), e);
        }
    }
}
