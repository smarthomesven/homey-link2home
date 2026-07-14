'use strict';

const Homey = require('homey');
const RELAY_INDEX = 1;

module.exports = class MyDevice extends Homey.Device {

  /**
   * onInit is called when the device is initialized.
   */
  async onInit() {
    this.log('MyDevice has been initialized');
    const data = this.getData();
    const store = this.getStore();
    this.deviceMeta = {
      macAddress: data.id,
      companyCode: store.companyCode,
      deviceType: store.deviceType,
      authCode: store.authCode,
    };
    this._onFrame = this._onFrame.bind(this);
    this.registerCapabilityListener('onoff', this._onCapabilityOnoff.bind(this));
    await this.homey.app.registerDevice(this.deviceMeta, this._onFrame);
  }

  async _onCapabilityOnoff(value) {
    this.log('Setting onoff ->', value);
    await this.homey.app.sendPower(this.deviceMeta, RELAY_INDEX, value);
  }

  _onFrame(parsed) {
    const isStatusFrame = parsed.commandCode === 2 || parsed.commandCode === 3 || parsed.commandCode === 18;
    if (!isStatusFrame || parsed.payload.length < 3) return;

    const relayIndex = parsed.payload[1];
    const state = parsed.payload[2];
    if (relayIndex !== RELAY_INDEX) return;

    const isOn = state !== 0;
    this.log(`Status push (cmd ${parsed.commandCode}): relay ${relayIndex} is ${isOn ? 'on' : 'off'}`);
    if (this.hasCapability('onoff')) {
      this.setCapabilityValue('onoff', isOn).catch((err) => {
        this.error('Failed to set onoff capability:', err);
      });
    }
  }

  /**
   * onAdded is called when the user adds the device, called just after pairing.
   */
  async onAdded() {
    this.log('MyDevice has been added');
  }

  /**
   * onSettings is called when the user updates the device's settings.
   * @param {object} event the onSettings event data
   * @param {object} event.oldSettings The old settings object
   * @param {object} event.newSettings The new settings object
   * @param {string[]} event.changedKeys An array of keys changed since the previous version
   * @returns {Promise<string|void>} return a custom message that will be displayed
   */
  async onSettings({ oldSettings, newSettings, changedKeys }) {
    this.log('MyDevice settings where changed');
  }

  /**
   * onRenamed is called when the user updates the device's name.
   * This method can be used this to synchronise the name to the device.
   * @param {string} name The new name
   */
  async onRenamed(name) {
    this.log('MyDevice was renamed');
  }

  /**
   * onDeleted is called when the user deleted the device.
   */
  async onDeleted() {
    this.log('MyDevice has been deleted');
    this.homey.app.unregisterDevice(this.deviceMeta.macAddress, this._onFrame);
  }

};
