'use strict';

const dgram = require('dgram');

const LAN_PORT = 35932;

/* ============================================================
 * Frame format (traced from r.f.a() + p.b's length-field decoder)
 *
 *   0      : 0xA1                       fixed magic
 *   1      : flags (bit 2 = wifiLocked)
 *   2-7    : MAC address (6 bytes)
 *   8-9    : length field, BE = payloadLength + 6
 *   10-11  : protocolIndex (sequence number), BE
 *   12     : companyCode
 *   13     : deviceType
 *   14-15  : authCode, BE
 *   16+    : payload (first byte = command code)
 * ============================================================ */

let protocolIndexCounter = 0;
function nextProtocolIndex() {
  const v = protocolIndexCounter;
  protocolIndexCounter = (protocolIndexCounter + 1) % 32768;
  return v;
}

function macToBytes(macHex) {
  const clean = macHex.replace(/[:\-]/g, '');
  if (clean.length !== 12) throw new Error('MAC must be 6 bytes (12 hex chars)');
  const bytes = Buffer.alloc(6);
  for (let i = 0; i < 6; i++) bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  return bytes;
}

function macToString(buf) {
  return buf.toString('hex').toUpperCase();
}

/**
 * device: {
 *   macAddress: '12 hex chars, no separators',
 *   companyCode: number (0-255),
 *   deviceType: number (0-255)   // 0xD1 for your plug
 *   authCode: number (0-65535),
 *   wifiLocked?: boolean,
 *   protocolIndex?: number       // omit to auto-increment
 * }
 * Pass device = null for protocol-level frames (discovery/heartbeat) that
 * aren't addressed to one specific paired device.
 */
function buildFrame(device, ...payloadParts) {
  const payload = Buffer.concat(payloadParts.map((p) => Buffer.from(p)));
  const frame = Buffer.alloc(16 + payload.length);

  frame[0] = 0xa1;

  if (device) {
    frame[1] = device.wifiLocked ? 4 : 0;
    macToBytes(device.macAddress).copy(frame, 2);
  }

  frame.writeUInt16BE(payload.length + 6, 8);

  const protocolIndex =
    device && device.protocolIndex != null ? device.protocolIndex : nextProtocolIndex();
  frame.writeUInt16BE(protocolIndex, 10);

  if (device) {
    frame[12] = device.companyCode & 0xff;
    frame[13] = device.deviceType & 0xff;
    frame.writeUInt16BE(device.authCode & 0xffff, 14);
  }

  payload.copy(frame, 16);
  return frame;
}

/**
 * Parses any received frame back into its fields. Works for both replies
 * to a specific device and broadcast-discovery replies.
 */
function parseFrame(buf) {
  if (buf.length < 16) throw new Error(`Frame too short: ${buf.length} bytes`);
  const contentLength = buf.readUInt16BE(8);
  const expectedTotal = 10 + contentLength;
  return {
    magic: buf[0],
    flags: buf[1],
    macAddress: macToString(buf.subarray(2, 8)),
    contentLength,
    protocolIndex: buf.readUInt16BE(10),
    companyCode: buf[12],
    deviceType: buf[13],
    authCode: buf.readUInt16BE(14),
    payload: buf.subarray(16),
    commandCode: buf.length > 16 ? buf[16] : null,
    totalLength: buf.length,
    lengthFieldMatches: buf.length === expectedTotal, // sanity check
  };
}

/* ------------------------------------------------------------
 * r.c commands (per-device control — deviceType 0xD1 is in this family)
 * ---------------------------------------------------------- */

function powerToggle(device, relayIndex, on) {
  // r.c.o(device, idx, on) -> {1, idx, on ? 0xFF : 0x00}
  return buildFrame(device, Buffer.from([1, relayIndex & 0xff, on ? 0xff : 0x00]));
}

function queryStatus(device) {
  // r.c.l(device) -> {20}
  return buildFrame(device, Buffer.from([20]));
}

function setCountdown(device, relayIndex, on, seconds) {
  // r.c.q(device, idx, on, int32) -> {10, idx, on, seconds BE}
  const buf = Buffer.alloc(4);
  buf.writeInt32BE(seconds, 0);
  return buildFrame(device, Buffer.from([10, relayIndex & 0xff, on ? 1 : 0]), buf);
}

/* ------------------------------------------------------------
 * r.g protocol-level commands (discovery / heartbeat)
 * ---------------------------------------------------------- */

const BROADCAST_MAC = 'FFFFFFFFFFFF';

function discoveryBroadcast(companyCode, deviceType) {
  // r.g.d(companyCode, deviceType) -> {35}, MAC forced to broadcast
  return buildFrame(
    { macAddress: BROADCAST_MAC, companyCode, deviceType, authCode: 0 },
    Buffer.from([35])
  );
}

function heartbeat(device) {
  // r.g.g(device) -> {97}
  return buildFrame(device, Buffer.from([97]));
}

/* ============================================================
 * UDP client
 * ============================================================ */

class Link2HomeClient {
  constructor() {
    this.socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    this._listeners = [];

    this.socket.on('message', (msg, rinfo) => {
      let parsed;
      try {
        parsed = parseFrame(msg);
      } catch (e) {
        console.error('Failed to parse incoming frame:', e.message, msg.toString('hex'));
        return;
      }
      for (const listener of this._listeners) listener(parsed, rinfo, msg);
    });
  }

  /**
   * Resolves once the socket is bound and broadcast-capable.
   * Defaults to the protocol's fixed port (35932) rather than an ephemeral
   * one: the decompiled code hardcodes 35932 as both source and destination
   * everywhere, suggesting the plug replies to that fixed port regardless
   * of the request's source port.
   */
  bind(port = LAN_PORT) {
    return new Promise((resolve, reject) => {
      this.socket.once('error', reject);
      this.socket.bind(port, () => {
        this.socket.setBroadcast(true);
        this.socket.removeListener('error', reject);
        console.log('Bound to', this.socket.address());
        resolve(this.socket.address());
      });
    });
  }

  /** Register a callback for every parsed incoming frame. */
  onFrame(callback) {
    this._listeners.push(callback);
    return () => {
      this._listeners = this._listeners.filter((l) => l !== callback);
    };
  }

  send(frame, host, port = LAN_PORT) {
    return new Promise((resolve, reject) => {
      this.socket.send(frame, port, host, (err) => (err ? reject(err) : resolve()));
    });
  }

  /**
   * Broadcasts a discovery frame and collects replies for `timeoutMs`.
   * Returns an array of { parsed, rinfo }.
   */
  discover(companyCode, deviceType, broadcastAddress = '255.255.255.255', timeoutMs = 3000) {
    return new Promise((resolve, reject) => {
      const found = [];
      const off = this.onFrame((parsed, rinfo) => {
        if (parsed.macAddress !== BROADCAST_MAC) {
          found.push({ parsed, rinfo });
        }
      });

      const frame = discoveryBroadcast(companyCode, deviceType);
      this.send(frame, broadcastAddress, LAN_PORT).catch(reject);

      setTimeout(() => {
        off();
        resolve(found);
      }, timeoutMs);
    });
  }

  /** Turns a specific device's relay on/off and returns as soon as sent. */
  async setPower(device, relayIndex, on) {
    const frame = powerToggle(device, relayIndex, on);
    await this.send(frame, device.localIpAddress);
    return frame;
  }

  async getStatus(device) {
    const frame = queryStatus(device);
    await this.send(frame, device.localIpAddress);
    return frame;
  }

  close() {
    this.socket.close();
  }
}

module.exports = {
  LAN_PORT,
  BROADCAST_MAC,
  buildFrame,
  parseFrame,
  macToBytes,
  macToString,
  powerToggle,
  queryStatus,
  setCountdown,
  discoveryBroadcast,
  heartbeat,
  Link2HomeClient,
};