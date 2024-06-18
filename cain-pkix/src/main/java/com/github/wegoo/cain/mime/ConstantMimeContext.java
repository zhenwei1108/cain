package com.github.wegoo.cain.mime;

import java.io.IOException;
import java.io.InputStream;

public class ConstantMimeContext
    implements MimeContext, MimeMultipartContext
{

    public static final ConstantMimeContext Instance = new ConstantMimeContext();

    public InputStream applyContext(Headers headers, InputStream contentStream)
        throws IOException
    {
        return contentStream;
    }

    public MimeContext createContext(int partNo)
        throws IOException
    {
        return this;
    }
}
