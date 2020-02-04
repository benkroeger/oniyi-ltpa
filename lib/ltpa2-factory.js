'use strict';

// node core modules

// 3rd party modules

// internal modules
const {
  readKeyfile,
  makeLtpaToken2,
  getSecretKey,
  getLtpaToken2Content,
  getLtpaTokenContent,
  makeLtpaBodyObject,
} = require('./ltpa-utils');

const { bufferToRSAPrivateKeyPEM } = require('./rsa-key-helper');

const factory = (keyfilePath, password, cb, config) => {
  // if the keyfilePath is not provided, but the config is.
  if (!config && !(keyfilePath && typeof keyfilePath === 'string')) {
    cb(new TypeError('first argument must be path to ltpa key file'));
    return;
  }

  if (!(password && typeof password === 'string')) {
    cb(new TypeError('second argument must be ltpa key password as string'));
    return;
  }

  if (config) {
    const { des3Key, privateKey } = config;
    const DES_EDE_3_KEY = getSecretKey(des3Key, password);
    const decryptedPrivateKeyBuffer = getSecretKey(privateKey, password);
    const privateKeyPEM = bufferToRSAPrivateKeyPEM(decryptedPrivateKeyBuffer);

    cb(null, {
      makeToken: content =>
        makeLtpaToken2(content, privateKeyPEM, DES_EDE_3_KEY),
    });

    return;
  }

  readKeyfile(keyfilePath, (readKeyfileError, keyfile) => {
    if (readKeyfileError) {
      cb(readKeyfileError);
      return;
    }

    // pick required props from keyfile
    const { des3Key, privateKey } = keyfile;

    // decrypt the information from ltpa key file and generate PEM formatted RSA private key
    const DES_EDE_3_KEY = getSecretKey(des3Key, password);
    const decryptedPrivateKeyBuffer = getSecretKey(privateKey, password);
    const privateKeyPEM = bufferToRSAPrivateKeyPEM(decryptedPrivateKeyBuffer);

    cb(null, {
      // always return a copy to prevent external modification and also include the computed privateKeyPEM
      getKeyfile: () => ({ ...keyfile, privateKeyPEM }),
      // decode token and return content with `body` portion parsed to object
      decode: token => {
        const content = getLtpaToken2Content(token, DES_EDE_3_KEY);
        Object.assign(content, {
          body: makeLtpaBodyObject(content.body),
        });

        return content;
      },
      decodeV1: token => {
        const content = getLtpaTokenContent(token, DES_EDE_3_KEY);
        Object.assign(content, {
          body: makeLtpaBodyObject(content.body),
        });

        return content;
      },
      makeToken: content =>
        makeLtpaToken2(content, privateKeyPEM, DES_EDE_3_KEY),
    });
  });
};

module.exports = factory;
