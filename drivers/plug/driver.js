'use strict';

const Homey = require('homey');
const axios = require('axios');
const { withSignature } = require('../../lib/sign');
const crypto = require('crypto');

module.exports = class PlugDriver extends Homey.Driver {

  /**
   * onInit is called when the driver is initialized.
   */
  async onInit() {
    this.log('Indoor socket driver has been initialized');
  }

  async onPair(session) {
    session.setHandler("login", async (data) => {
      try {
        const email = data.email;
        const password = data.password;
        if (!email || !password) {
          return false;
        }
        this.log('Attempting login with email:', email);
        const passwordMd5 = crypto.createHash('md5').update(password, 'utf8').digest('hex').toUpperCase();
        const params = withSignature({
          username: email,
          password: passwordMd5,
          phoneType: 'sdk_gphone64_x86_64',
          appVersion: '1.1.84',
          appType: '1',
          appName: 'Link2Home',
          phoneSysVersion: 'Android:16',
        });
        const response = await axios.post('https://userdata.link2home.com/api/service/user/login', new URLSearchParams(params).toString(), {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        });
        this.log('Login response:', response.data);
        const token = response.data?.data?.token;
        if (!token) {
          return false;
        }
        this.homey.settings.set('token', token);
        this.homey.app.setCredentials(email, passwordMd5);
        await session.showView('list_devices');
        return true;
      } catch (error) {
        this.error('Login error:', error);
        return false;
      }
    });

    session.setHandler("list_devices", async () => {
      try {
        const token = this.homey.settings.get('token');
        if (!token) {
          throw new Error('No token found. Please log in first.');
        }
        const params = withSignature({ token });
        const qs = new URLSearchParams(params).toString();
        const response = await axios.get(`https://userdata.link2home.com/api/app/device/list?${qs}`);
        const devices = response.data?.data || [];
        return devices
        .filter (device => device.deviceType === 'D1')
        .map(device => ({
          name: device.deviceName,
          data: {
            id: device.macAddress,
          },
          store: {
            authCode: parseInt(device.authCode, 10),
            companyCode: parseInt(device.companyCode, 16),
            deviceType: parseInt(device.deviceType, 16),
          }
        }));
      } catch (error) {
        this.error('Error listing devices:', error);
        return [];
      }
    });
  }

  /**
   * onPairListDevices is called when a user is adding a device
   * and the 'list_devices' view is called.
   * This should return an array with the data of devices that are available for pairing.
   */
  async onPairListDevices() {
    return [
      // Example device data, note that `store` is optional
      // {
      //   name: 'My Device',
      //   data: {
      //     id: 'my-device',
      //   },
      //   store: {
      //     address: '127.0.0.1',
      //   },
      // },
    ];
  }

};
