package com.github.wegoo.cain.pkix.util.filter;

/**
 * 
 * Wrapper class to mark an untrusted Url
 */
public class UntrustedUrlInput extends UntrustedInput
{
    public UntrustedUrlInput(Object url)
    {
        super(url);
    }
    
}
