package com.github.wegoo.cain.engine.base;

import com.github.wegoo.cain.engine.params.KeyParams;
import java.security.KeyPair;

public interface BaseProvider {

  void init(Object obj);

  KeyPair generateKeyPair(KeyParams keyParams);



}
