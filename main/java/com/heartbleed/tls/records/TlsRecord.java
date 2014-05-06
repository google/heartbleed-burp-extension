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
import com.heartbleed.tls.TlsVersion;

public class TlsRecord {

  protected final byte[] recordBytes;
  protected TlsRecord(byte[] recordBytes) {
    Preconditions.checkArgument(recordBytes.length >= 5);
    this.recordBytes = recordBytes;
  }

  public static TlsRecord tlsRecordForBytes(byte[] bytes) {
    switch (ContentType.typeForByte(bytes[0])) {
      case HANDSHAKE:
        return new HandshakeRecord(bytes);
      case ALERT:
        return new AlertRecord(bytes);
      case HEARTBEAT:
        return new HeartbeatResponseMessage(bytes);
      default:
        return new TlsRecord(bytes);
    }
  }

  TlsVersion getRecordVersion() {
    byte[] recordVersion = { recordBytes[1], recordBytes[2] };
    for (TlsVersion version : TlsVersion.values()) {
      byte [] versionBytes = version.getBytes();
      if (recordVersion[0] == versionBytes[0] &&
          recordVersion[1] == versionBytes[1]) {
        return version;
      }
    }
    throw new IllegalStateException(
        String.format("Unknown TLS version %02x %02x", recordVersion[0], recordVersion[1]));
  }

  public ContentType getContentType() {
    for (ContentType type : ContentType.values()) {
      if (recordBytes[0] == type.getBytes()) {
        return type;
      }
    }
    throw new IllegalStateException(
        String.format("Unknown record type %02x", recordBytes[0]));
  }

  public int getRecordLength() {
    return recordBytes.length - 5;
  }

  public byte[] getRecordBytes() {
    return recordBytes;
  }
}
