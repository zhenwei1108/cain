package com.github.wegoo.cain.cms;

import java.io.OutputStream;

interface CMSSecureReadableWithAAD
    extends CMSSecureReadable
{
    void setAADStream(OutputStream stream);

    OutputStream getAADStream();

    byte[] getMAC();
}
