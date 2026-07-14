'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// NOTE: for starting this app using CLI you need to extract this private key from the Android app, it's not included on GitHub for security reasons.
const PRIVATE_KEY_PEM = fs.readFileSync(
  path.join(__dirname, '../l2h_privatekey.pem'),
  'utf8'
);

/**
 * Mirrors g(map) from the decompiled code: sort keys, join as
 * key1=value1&key2=value2&... (no params object mutation, 'sign' itself
 * must NOT be included).
 */
function buildSigningString(params) {
  const keys = Object.keys(params).sort();
  return keys.map((k) => `${k}=${params[k]}`).join('&');
}

/**
 * Mirrors f() + a(): SHA1withRSA (== RSA-SHA1 / PKCS#1 v1.5) sign, then
 * base64-encode. Node's default sign() padding is RSA_PKCS1_PADDING, which
 * matches Java's default Signature padding for RSA - no special options
 * needed.
 */
function signParams(params) {
  const signingString = buildSigningString(params);
  const signer = crypto.createSign('RSA-SHA1');
  signer.update(signingString, 'utf8');
  signer.end();
  const signature = signer.sign(PRIVATE_KEY_PEM); // Buffer
  return signature.toString('base64');
}

/**
 * Convenience: takes your request params, computes+adds 'sign', and
 * returns a URLSearchParams ready to POST as
 * application/x-www-form-urlencoded, or to append to a GET query string.
 */
function withSignature(params) {
  const sign = signParams(params);
  return { ...params, sign };
}

module.exports = { buildSigningString, signParams, withSignature };