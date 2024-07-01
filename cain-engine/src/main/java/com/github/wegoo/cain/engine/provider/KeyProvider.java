package com.github.wegoo.cain.engine.provider;

import com.github.wegoo.cain.engine.base.BaseProvider;
import com.github.wegoo.cain.engine.params.KeyParamsEnum;
import com.github.wegoo.cain.jce.provider.CainJCEProvider;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;

public class KeyProvider implements BaseProvider {

  private Provider provider;

  @Override
  public void init(Object obj) {
    this.provider = new CainJCEProvider();
    Security.addProvider(provider);
  }

  @Override
  public KeyPair generateKeyPair(KeyParamsEnum keyParams) {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance(keyParams.getKeyAlg().name(),
          provider);
      generator.initialize(keyParams.getKeyLen());
      return generator.generateKeyPair();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
