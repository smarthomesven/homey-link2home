'use strict';

const Homey = require('homey');
const {
  RelaySocket,
  RELAY_HOST,
  RELAY_PORT,
  workServerRequestFrame,
  loginFrame,
  subscribeFrames,
  parseWorkServerAddress,
} = require('./lib/relay');
const { powerToggle, queryStatus, heartbeat } = require('./lib/protocol');

module.exports = class Link2HomeApp extends Homey.App {
  async onInit() {
    this.log('Link2Home app initializing');

    this._workSocket = null;
    this._connectingPromise = null;
    this._deviceMeta = new Map();
    this._deviceListeners = new Map();
    this._subscribedMacs = new Set();
    this._heartbeatTimer = null;
    this._reconnectTimer = null;
    this._reconnectDelayMs = 1000;
    this._reconnectDelayMaxMs = 30000;
    this._destroyed = false;
  }

  async onUninit() {
    this._destroyed = true;
    this._stopHeartbeat();
    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }
    if (this._workSocket) {
      this._workSocket.close();
      this._workSocket = null;
    }
  }

  setCredentials(username, passwordMd5) {
    this.homey.settings.set('username', username);
    this.homey.settings.set('passwordMd5', passwordMd5);
  }

  async registerDevice(deviceMeta, onFrame) {
    this._deviceMeta.set(deviceMeta.macAddress, deviceMeta);

    if (!this._deviceListeners.has(deviceMeta.macAddress)) {
      this._deviceListeners.set(deviceMeta.macAddress, new Set());
    }
    this._deviceListeners.get(deviceMeta.macAddress).add(onFrame);

    const ws = await this.getConnection();
    await this._subscribeIfNeeded(ws, deviceMeta);
  }

  unregisterDevice(macAddress, onFrame) {
    const listeners = this._deviceListeners.get(macAddress);
    if (listeners) listeners.delete(onFrame);
  }

  async sendPower(deviceMeta, relayIndex, on) {
    const ws = await this.getConnection();
    ws.send(powerToggle(deviceMeta, relayIndex, on));
  }

  async sendStatusQuery(deviceMeta) {
    const ws = await this.getConnection();
    ws.send(queryStatus(deviceMeta));
  }

  async getConnection() {
    if (this._workSocket && this._workSocket.socket && !this._workSocket.socket.destroyed) {
      return this._workSocket;
    }
    if (this._connectingPromise) {
      return this._connectingPromise;
    }
    this._connectingPromise = this._connect().finally(() => {
      this._connectingPromise = null;
    });
    return this._connectingPromise;
  }

  async _connect() {
    const username = this.homey.settings.get('username');
    const passwordMd5 = this.homey.settings.get('passwordMd5');
    if (!username || !passwordMd5) {
      throw new Error('No Link2Home credentials available yet - pair a device first.');
    }

    this.log('Connecting to load balancer', RELAY_HOST, RELAY_PORT);
    const lb = new RelaySocket(RELAY_HOST, RELAY_PORT);
    let workServer = null;
    const stopListening = lb.onFrame((parsed) => {
      if (parsed.commandCode === 0x81 && parsed.payload.length >= 7) {
        workServer = parseWorkServerAddress(parsed.payload);
      }
    });
    await lb.connect();
    lb.send(workServerRequestFrame());
    await this._waitUntil(() => workServer !== null, 5000);
    stopListening();
    lb.close();

    if (!workServer) {
      throw new Error('Did not receive a work-server address from the load balancer');
    }

    this.log('Connecting to work server', workServer.host, workServer.port);
    const ws = new RelaySocket(workServer.host, workServer.port);
    await ws.connect();

    ws.onFrame((parsed) => this._handleIncomingFrame(parsed));
    ws.socket.on('close', () => this._handleDisconnect());

    ws.send(loginFrame(username, passwordMd5));
    await this._sleep(1000);

    if (this._destroyed) {
      ws.close();
      return ws;
    }

    this._workSocket = ws;
    this._subscribedMacs.clear();
    this._reconnectDelayMs = 1000;

    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }

    for (const deviceMeta of this._deviceMeta.values()) {
      await this._subscribeIfNeeded(ws, deviceMeta);
    }

    if (this._destroyed) {
      ws.close();
      return ws;
    }

    this._startHeartbeat();

    return ws;
  }

  _startHeartbeat() {
    this._stopHeartbeat();
    this._heartbeatTimer = setInterval(() => {
      const ws = this._workSocket;
      if (!ws) return;
      for (const deviceMeta of this._deviceMeta.values()) {
        try {
          ws.send(heartbeat(deviceMeta));
        } catch (err) {
          this.error('Heartbeat send failed:', err);
        }
      }
    }, 20000);
  }

  _stopHeartbeat() {
    if (this._heartbeatTimer) {
      clearInterval(this._heartbeatTimer);
      this._heartbeatTimer = null;
    }
  }

  async _subscribeIfNeeded(ws, deviceMeta) {
    if (this._subscribedMacs.has(deviceMeta.macAddress)) return;
    this._subscribedMacs.add(deviceMeta.macAddress);
    for (const frame of subscribeFrames(deviceMeta)) {
      ws.send(frame);
      await this._sleep(300);
    }
  }

  _handleIncomingFrame(parsed) {
    const listeners = this._deviceListeners.get(parsed.macAddress);
    if (!listeners || listeners.size === 0) {
      this.log(
        `No registered listener for MAC ${parsed.macAddress} ` +
          `(commandCode ${parsed.commandCode}) - known devices: ` +
          `[${[...this._deviceMeta.keys()].join(', ')}]`
      );
      return;
    }
    for (const cb of listeners) {
      try {
        cb(parsed);
      } catch (err) {
        this.error('Device frame listener threw:', err);
      }
    }
  }

  _handleDisconnect() {
    this.log('Work-server connection closed; reconnecting shortly');
    this._workSocket = null;
    this._subscribedMacs.clear();
    this._stopHeartbeat();
    this._scheduleReconnect();
  }

  _scheduleReconnect() {
    if (this._destroyed) return;
    if (this._reconnectTimer) return;
    const delay = this._reconnectDelayMs;
    this.log(`Reconnecting in ${delay}ms`);
    this._reconnectTimer = setTimeout(() => {
      this._reconnectTimer = null;
      if (this._destroyed) return;
      this.getConnection().catch((err) => {
        this.error('Reconnect attempt failed:', err.message);
        this._reconnectDelayMs = Math.min(this._reconnectDelayMs * 2, this._reconnectDelayMaxMs);
        this._scheduleReconnect();
      });
    }, delay);
  }

  _waitUntil(predicate, timeoutMs) {
    return new Promise((resolve, reject) => {
      const start = Date.now();
      const tick = () => {
        if (predicate()) return resolve();
        if (Date.now() - start > timeoutMs) return reject(new Error('Timed out waiting'));
        setTimeout(tick, 100);
      };
      tick();
    });
  }

  _sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
};