'use strict';

// LTPA v2 will not use 3DES, but only AES
// node core modules
const crypto = require('crypto');
// 3rd party modules

// internal modules

const decrypt = (params) => {
  const {
    cyphertext, key, iv = Buffer.alloc(0), alg = 'DES-EDE3', autoPad = true,
  } = params;
  const ivBuffer = Buffer.from(iv);

  const decipher = crypto.createDecipheriv(alg, key, ivBuffer);
  decipher.setAutoPadding(autoPad);

  return Buffer.concat([decipher.update(cyphertext), decipher.final()]);
};

const encrypt = (params) => {
  const {
    cyphertext, key, iv = Buffer.alloc(0), alg = 'DES-EDE3', autoPad = true,
  } = params;
  const ivBuffer = Buffer.from(iv);

  const cipher = crypto.createCipheriv(alg, key, ivBuffer);
  cipher.setAutoPadding(autoPad);

  return Buffer.concat([cipher.update(cyphertext), cipher.final()]);
};

// when exporting ltpa keys from IBM WebSphere Application Server
// you need to perform further operations to get to the actual values.
// e.g. the property `com.ibm.websphere.ltpa.3DESKey` is a base64 encoded
// string, representing the result of `DES-EDE3` encrypting the actual
// 3DESKey with a key that was derived from SHA1 hashing the `password`
// and (right) padding the result with 0x0 bytes to a total length of 24 bytes.
// base64Encode(crypt(myActualKey, 'DES-EDE3', pad(sha1(password), 24)))
const SHA1Pad24 = (str) => {
  const messageDigest = crypto.createHash('sha1');
  messageDigest.update(Buffer.from(str));

  // the result of sha1 hash is always 20 bytes
  return Buffer.alloc(24, messageDigest.digest()).fill(0, 20);
};

const getSecretKey = (shared, password) => {
  const key = SHA1Pad24(password);
  const cyphertext = Buffer.from(shared, 'base64');

  return decrypt({ cyphertext, key });
};

module.exports = {
  decrypt,
  encrypt,
  SHA1Pad24,
  getSecretKey,
};
