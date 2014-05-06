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

public enum ContentType {
  CHANGE_CIPHER_SPEC((byte) 0x14),
  ALERT((byte) 0x15),
  HANDSHAKE((byte) 0x16),
  APPLICATION_DATA((byte) 0x17),
  HEARTBEAT((byte) 0x18);

  private final byte type;
  private ContentType(byte type) {
    this.type = type;
  }

  public byte getBytes() {
    return type;
  }

  public static ContentType typeForByte(byte b) {
    for (ContentType type : ContentType.values()) {
      if (b == type.getBytes()) {
        return type;
      }
    }
    throw new IllegalStateException(
        String.format("Unknown record type %02x", b));
  }
}
