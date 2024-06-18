package com.github.wegoo.cain.test;


import com.github.wegoo.cain.jce.provider.CainJCEProvider;
import com.github.wegoo.cain.util.encoders.Hex;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;

public class KyberTest {

  @Test
  public void encDec() throws  Exception {
    Security.addProvider(new CainJCEProvider());
    KeyPairGenerator generator = KeyPairGenerator.getInstance("Kyber", "CAIN");
    generator.initialize(2);
    KeyPair keyPair = generator.generateKeyPair();

    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "CAIN");
    keyGenerator.init(128);
    SecretKey secretKey = keyGenerator.generateKey();

    Cipher cipher = Cipher.getInstance("Kyber", "CAIN");
    cipher.init(Cipher.WRAP_MODE, keyPair.getPublic());
    byte[] bytes = cipher.wrap(secretKey);
    System.out.println(Hex.toHexString(bytes));

  }


}
