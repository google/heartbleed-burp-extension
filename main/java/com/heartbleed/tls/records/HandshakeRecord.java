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

public class HandshakeRecord extends TlsRecord {

  private static final byte SERVER_HELLO_DONE = 0x0E;

  protected HandshakeRecord(byte[] recordBytes) {
    super(recordBytes);
    Preconditions.checkState(getContentType() == ContentType.HANDSHAKE);
  }

  public boolean isServerHelloDone() {
    // 0   -> TLS record type
    // 1-2 -> TLS version
    // 3-4 -> record length
    // 5   -> msg_type 
    return recordBytes[5] == SERVER_HELLO_DONE;
  }
}