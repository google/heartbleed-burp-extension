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
package com.heartbleed.tls.records;

import com.google.common.base.Preconditions;

import com.heartbleed.tls.ContentType;

import java.nio.ByteBuffer;

public class HeartbeatResponseMessage extends TlsRecord {

  protected HeartbeatResponseMessage(byte[] recordBytes) {
    super(recordBytes);
    Preconditions.checkState(getContentType() == ContentType.HEARTBEAT);
  }

  public boolean responseContainsByteSequence(byte[] sequence) {
    Preconditions.checkState(recordBytes[5] == 0x02);
    ByteBuffer buffer = ByteBuffer.wrap(recordBytes);
    buffer.position(6);
    short payloadLength = buffer.getShort();

    for (int i = 0; i < payloadLength - sequence.length; i++) {
      int j;
      for (j = 0; j < sequence.length; j++) {
        if (recordBytes[8 + i + j] != sequence[j]) {
          break;
        }
      }
      if (j == sequence.length) {
        return true;
      }
    }
    return false;
  }
}
