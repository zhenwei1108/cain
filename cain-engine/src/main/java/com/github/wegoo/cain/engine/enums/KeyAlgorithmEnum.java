package com.github.wegoo.cain.engine.enums;

import com.github.wegoo.cain.engine.base.BaseAlgorithmEnum;

public enum KeyAlgorithmEnum implements BaseAlgorithmEnum {
  SM2("SM2","asym"),
  RSA("RSA","asym"),

  ;

  String algorithm;
  /**
   * asym = 非对称
   * sym = 对称
   * hash = 摘要
   *
   */
  String keyType;

  KeyAlgorithmEnum(String algorithm, String keyType) {
    this.algorithm = algorithm;
    this.keyType = keyType;
  }

  @Override
  public String getAlgorithm() {
    return null;
  }
}
