/*
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */
package com.heartbleed.tls;

/**
 * See http://tools.ietf.org/html/rfc5246#page-75
 */
public enum CipherSuite {
  TLS_RSA_WITH_NULL_MD5((byte) 0x00, (byte) 0x01),
  TLS_RSA_WITH_NULL_SHA((byte) 0x0, (byte) 0x02),
  TLS_RSA_WITH_NULL_SHA256((byte) 0x00, (byte) 0x3B),
  TLS_RSA_WITH_RC4_128_MD5((byte) 0x00, (byte) 0x04),
  TLS_RSA_WITH_RC4_128_SHA((byte) 0x00, (byte) 0x05),
  TLS_RSA_WITH_3DES_EDE_CBC_SHA((byte) 0x00, (byte) 0x0A),
  TLS_RSA_WITH_AES_128_CBC_SHA((byte) 0x00, (byte) 0x2F),
  TLS_RSA_WITH_AES_256_CBC_SHA((byte) 0x00, (byte) 0x35),
  TLS_RSA_WITH_AES_128_CBC_SHA256((byte) 0x00, (byte) 0x3C),
  TLS_RSA_WITH_AES_256_CBC_SHA256((byte) 0x00, (byte) 0x3D);

  private final byte upper, lower;
  CipherSuite(byte upper, byte lower) {
    this.upper = upper;
    this.lower = lower;
  }

  public byte[] getBytes() {
    return new byte[] { upper, lower };
  }
}
