'use strict';

const tls = require('tls');
const { buildFrame, parseFrame } = require('./protocol');

// From q.b: production host/port for the load-balancer entry point.
const RELAY_HOST = 'userdata.link2home.com';
const RELAY_PORT = 33491;

// q.b.f6063b - fixed 8-byte blob included in every login frame.
const LOGIN_FIXED_BLOB = Buffer.from([0x00, 0x00, 0x01, 0x5b, 0x8f, 0xf1, 0x3b, 0x43]);

// o0.a.d() default branch (f5711a == false, the normal case).
const CLIENT_ID = Buffer.from('Link2Home', 'utf8');

/**
 * r.g.f() -> payload {0x81}, no device.
 * Ask the load balancer for a work-server address.
 */
function workServerRequestFrame() {
  return buildFrame(null, Buffer.from([0x81]));
}

/**
 * r.g.h(username, passwordHash) -> payload:
 *   0x82, len(fixedBlob), fixedBlob,
 *   len(username), username,
 *   len(passwordHash), passwordHash,
 *   len(clientId), clientId
 *
 * passwordHash is the same MD5 hex string used in the HTTP login's
 * `password` field (uppercase hex, 32 chars) - NOT a fresh MD5 of anything
 * else. Pass it through exactly as captured from your HTTP login request.
 */
function loginFrame(username, passwordHashHex) {
  const usernameBuf = Buffer.from(username, 'utf8');
  const passwordBuf = Buffer.from(passwordHashHex, 'utf8');

  return buildFrame(
    null,
    Buffer.from([0x82, LOGIN_FIXED_BLOB.length]),
    LOGIN_FIXED_BLOB,
    Buffer.from([usernameBuf.length]),
    usernameBuf,
    Buffer.from([passwordBuf.length]),
    passwordBuf,
    Buffer.from([CLIENT_ID.length]),
    CLIENT_ID
  );
}

/**
 * r.g.m(device, true) -> {0x86, 1, -124(0x84), 0}
 * r.c.s(device, true)  -> {0x86, 1, 3, 0}
 * r.c.t(device, true,1) -> {0x86, 1, 3, 1}
 * r.c.t(device, true,2) -> {0x86, 1, 3, 2}
 * r.g.j(device)         -> {0x83}
 * Sent once per device right after WORK_SERVER_JOINED, per protocol.procedure.e.j()
 */
function subscribeFrames(device) {
  return [
    buildFrame(device, Buffer.from([0x86, 1, 0x84, 0])),
    buildFrame(device, Buffer.from([0x86, 1, 3, 0])),
    buildFrame(device, Buffer.from([0x86, 1, 3, 1])),
    buildFrame(device, Buffer.from([0x86, 1, 3, 2])),
    buildFrame(device, Buffer.from([0x83])),
  ];
}

/**
 * The load balancer's reply to workServerRequestFrame() has payload:
 *   [0x81 (echoed command), ip0, ip1, ip2, ip3, portHi, portLo]
 * IP is a plain dotted-quad in normal network byte order; port is BE,
 * consistent with every other multi-byte field in this protocol.
 */
function parseWorkServerAddress(payload) {
  if (payload.length < 7) {
    throw new Error(`Work-server address payload too short: ${payload.length} bytes`);
  }
  const host = `${payload[1]}.${payload[2]}.${payload[3]}.${payload[4]}`;
  const port = payload.readUInt16BE(5);
  return { host, port };
}

/**
 * Reassembles a TCP byte stream into complete frames, mirroring p.b's
 * logic: read until you have 10 header bytes, read the BE uint16 length
 * field at offset 8, then wait for that many more bytes.
 */
class FrameStreamDecoder {
  constructor() {
    this.buffer = Buffer.alloc(0);
  }

  /** Feed newly-received bytes; returns an array of zero or more complete frames. */
  push(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    const frames = [];
    for (;;) {
      if (this.buffer.length < 10) break;
      const contentLength = this.buffer.readUInt16BE(8);
      const totalLength = 10 + contentLength;
      if (this.buffer.length < totalLength) break;
      frames.push(Buffer.from(this.buffer.subarray(0, totalLength)));
      this.buffer = this.buffer.subarray(totalLength);
    }
    return frames;
  }
}

/**
 * A single TLS connection to either the load balancer or a work server.
 * Emits parsed frames as they arrive; write() sends a raw frame Buffer.
 */
class RelaySocket {
  /**
   * strictTls: true would enforce normal certificate-chain validation.
   * Defaults to false because the vendor's own gs_intermediate_ca cert
   * expired 2024-02-20 - the server still presents a chain through it,
   * and the official app's own TrustManager (m0.a) evidently doesn't
   * enforce expiration either, which is why the app still works against
   * it. Traffic is still fully TLS-encrypted either way; this only skips
   * validating the server's certificate chain/expiry, which matters if
   * you're worried about an active MITM on the path to their server -
   * not a concern for most home/office networks, but worth knowing.
   */
  constructor(host, port, { strictTls = false } = {}) {
    this.host = host;
    this.port = port;
    this.strictTls = strictTls;
    this.decoder = new FrameStreamDecoder();
    this._frameListeners = [];
    this.socket = null;
  }

  connect() {
    return new Promise((resolve, reject) => {
      if (!this.strictTls) {
        console.warn(
          `Connecting to ${this.host}:${this.port} without certificate validation ` +
            '(vendor cert chain is expired - see comment above). Encrypted, not authenticated.'
        );
      }
      this.socket = tls.connect(
        { host: this.host, port: this.port, rejectUnauthorized: this.strictTls },
        () => {
          console.log(`TLS connected to ${this.host}:${this.port}`);
          // The ~45s idle disconnects observed in practice look like a NAT/
          // load-balancer idle-connection timeout rather than an app-level
          // session expiry. TCP keepalive alone may not be enough against
          // middleboxes that specifically watch for real payload traffic,
          // but it's cheap and standard to enable regardless.
          this.socket.setKeepAlive(true, 15000);
          resolve();
        }
      );

      this.socket.on('data', (chunk) => {
        const frames = this.decoder.push(chunk);
        for (const raw of frames) {
          let parsed;
          try {
            parsed = parseFrame(raw);
          } catch (e) {
            console.error('Failed to parse frame:', e.message, raw.toString('hex'));
            continue;
          }
          console.log('<< frame:', raw.toString('hex'));
          console.log('   parsed:', parsed);
          for (const listener of this._frameListeners) listener(parsed, raw);
        }
      });

      this.socket.on('error', (err) => {
        console.error(`TLS error (${this.host}:${this.port}):`, err.message);
        reject(err);
      });

      this.socket.on('close', () => {
        console.log(`Connection closed: ${this.host}:${this.port}`);
      });
    });
  }

  onFrame(callback) {
    this._frameListeners.push(callback);
    return () => {
      this._frameListeners = this._frameListeners.filter((l) => l !== callback);
    };
  }

  send(frame) {
    console.log(`>> sending to ${this.host}:${this.port}:`, frame.toString('hex'));
    this.socket.write(frame);
  }

  close() {
    if (this.socket) this.socket.end();
  }
}

module.exports = {
  RELAY_HOST,
  RELAY_PORT,
  workServerRequestFrame,
  loginFrame,
  subscribeFrames,
  parseWorkServerAddress,
  FrameStreamDecoder,
  RelaySocket,
};