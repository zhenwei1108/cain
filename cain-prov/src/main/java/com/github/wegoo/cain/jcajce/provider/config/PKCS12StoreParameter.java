package com.github.wegoo.cain.jcajce.provider.config;

import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStore.ProtectionParameter;

/**
 * @deprecated use com.github.wegoo.cain.jcajce.PKCS12StoreParameter
 */
public class PKCS12StoreParameter
    extends com.github.wegoo.cain.jcajce.PKCS12StoreParameter
{
    public PKCS12StoreParameter(OutputStream out, char[] password)
    {
        super(out, password, false);
    }

    public PKCS12StoreParameter(OutputStream out, ProtectionParameter protectionParameter)
    {
        super(out, protectionParameter, false);
    }

    public PKCS12StoreParameter(OutputStream out, char[] password, boolean forDEREncoding)
    {
        super(out, new KeyStore.PasswordProtection(password), forDEREncoding);
    }

    public PKCS12StoreParameter(OutputStream out, ProtectionParameter protectionParameter, boolean forDEREncoding)
    {
        super(out, protectionParameter, forDEREncoding);
    }
}
