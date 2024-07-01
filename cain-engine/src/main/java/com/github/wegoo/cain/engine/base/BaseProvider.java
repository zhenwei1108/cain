package com.github.wegoo.cain.engine.base;

import com.github.wegoo.cain.engine.params.KeyParams;
import com.github.wegoo.cain.engine.params.KeyParamsEnum;
import java.security.KeyPair;

public interface BaseProvider {

  void init(Object obj);

  KeyPair generateKeyPair(KeyParamsEnum keyParams);



}
