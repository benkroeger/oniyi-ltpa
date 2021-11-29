'use strict';

// LTPA v2 will not use 3DES, but only AES
// node core modules
const crypto = require('crypto');
const path = require('path');

// 3rd party modules
const properties = require('properties');

// internal modules
const { decrypt, encrypt, getSecretKey } = require('./utils/crypto-utils');

const {
  VERSION,
  DES3_KEY,
  PRIVATE_KEY,
  REALM,
  CREATION_DATE,
  CREATION_HOST,
  PUBLIC_KEY,
} = require('./constants');

const keyFilePropsMap = {
  [VERSION]: 'version',
  [CREATION_DATE]: 'creationDate',
  [CREATION_HOST]: 'creationHost',
  [REALM]: 'realm',
  [PUBLIC_KEY]: 'publicKey',
  [DES3_KEY]: 'des3Key',
  [PRIVATE_KEY]: 'privateKey',
};

const readKeyfile = (filePath, cb) => {
  properties.parse(
    path.resolve(process.cwd(), filePath),
    { path: true },
    (error, propertiesFileContent) => {
      if (error) {
        cb(error);
        return;
      }

      const keyFileContents = Object.keys(keyFilePropsMap).reduce(
        (result, key) => {
          const { [key]: propName } = keyFilePropsMap;
          const { [key]: value } = propertiesFileContent;
          return Object.assign(result, { [propName]: value });
        },
        {},
      );

      cb(null, keyFileContents);
    },
  );
};

const makeLtpaBodyObject = body =>
  body.split('$').reduce((result, entry) => {
    const [name, ...vals] = entry.split(':');
    return Object.assign(result, {
      [name]: Array.isArray(vals) ? vals.join(':') : vals,
    });
  }, {});

const makeLtpaBodyString = ({ expire, u }) =>
  [`expire:${expire}`, `u:${u}`].join('$');

const decryptLtpaToken = (shared, key) => {
  const cyphertext = Buffer.from(shared, 'base64');
  return decrypt({ cyphertext, key });
};

const decryptLtpaToken2 = (shared, key) => {
  const AESKey = Buffer.alloc(16);
  key.copy(AESKey, 0, 0, 16);

  const cyphertext = Buffer.from(shared, 'base64');
  const alg = 'AES-128-CBC';
  const iv = Buffer.from(AESKey);
  return decrypt({
    cyphertext,
    key: AESKey,
    alg,
    iv,
  });
};

const getLtpaTokenContent = (encryptedLtpaToken, key) => {
  const idxToNameMap = ['body', 'expires', 'signature'];

  const decryptedLtpaTokenBuffer = decryptLtpaToken(encryptedLtpaToken, key);
  const decryptedLtpaTokenParts = decryptedLtpaTokenBuffer
    .toString()
    .split('%');

  return decryptedLtpaTokenParts.reduce(
    (result, val, idx) => Object.assign(result, { [idxToNameMap[idx]]: val }),
    {},
  );
};

const getLtpaToken2Content = (encryptedLtpaToken2, key) => {
  const idxToNameMap = ['body', 'expires', 'signature'];

  const decryptedLtpaToken2Buffer = decryptLtpaToken2(encryptedLtpaToken2, key);
  const decryptedLtpaToken2Parts = decryptedLtpaToken2Buffer
    .toString()
    .split('%');

  return decryptedLtpaToken2Parts.reduce(
    (result, val, idx) => Object.assign(result, { [idxToNameMap[idx]]: val }),
    {},
  );
};

const signLtpaToken2 = (body, privateKey) => {
  const hashAlg = 'sha1WithRSAEncryption';
  const hashedBody = crypto
    .createHash('sha1')
    .update(Buffer.from(body))
    .digest();
  const signer = crypto.createSign(hashAlg);
  signer.update(hashedBody);
  return signer.sign(privateKey, 'base64');
};

const ensureExpires = (body, expire) => ({ ...body, expire });

// LTPA1 BASE64( RSA( SHA_DIGEST( token_body ) ) )
// LTPA2 BASE64( SHA1_WITH_RSA( SHA_DIGEST( token_body ) ) )
const makeLtpaToken2 = ({ body, expires }, signingKey, encryptionKey) => {
  const bodyString =
    typeof body === 'string'
      ? body
      : makeLtpaBodyString(ensureExpires(body, expires));
  const signature = signLtpaToken2(bodyString, signingKey);

  const rawToken = [bodyString, expires, signature].join('%');

  const AESKey = Buffer.alloc(16);
  encryptionKey.copy(AESKey, 0, 0, 16);

  const cyphertext = rawToken;
  const alg = 'AES-128-CBC';
  const iv = Buffer.from(AESKey);

  const encryptedTokenBuffer = encrypt({
    cyphertext,
    key: AESKey,
    alg,
    iv,
  });

  return encryptedTokenBuffer.toString('base64');
};

module.exports = {
  readKeyfile,
  makeLtpaToken2,
  getSecretKey,
  getLtpaTokenContent,
  getLtpaToken2Content,
  makeLtpaBodyObject,
};
