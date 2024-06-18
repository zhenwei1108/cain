package com.github.wegoo.cain.mime;

import java.io.IOException;
import java.io.InputStream;

public interface MimeContext
{
    InputStream applyContext(Headers headers, InputStream contentStream)
        throws IOException;
}