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

public enum TlsVersion {
  TLS_1_0((byte) 0x03, (byte) 0x01),
  TLS_1_1((byte) 0x03, (byte) 0x02),
  TLS_1_2((byte) 0x03, (byte) 0x03);

  private final byte majorVersion, minorVersion;
  private TlsVersion(byte major, byte minor) {
    this.majorVersion = major;
    this.minorVersion = minor;
  }

  public byte[] getBytes() {
    return new byte[]{ majorVersion, minorVersion};
  }
}