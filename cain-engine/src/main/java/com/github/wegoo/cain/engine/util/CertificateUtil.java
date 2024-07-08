package com.github.wegoo.cain.engine.util;

import com.github.wegoo.cain.asn1.x509.Certificate;

public class CertificateUtil {

  public static Certificate parseCert(byte[] cert){
    return Certificate.getInstance(cert);
  }

  public String getCertSN(byte[] cert){
    Certificate certificate = parseCert(cert);
    return certificate.getSerialNumber().toString();
  }

}
