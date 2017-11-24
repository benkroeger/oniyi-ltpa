'use strict';

// node core modules

// 3rd party modules
const BigIntegerBuffer = require('node-biginteger');
const BigInteger = require('big-integer');
const NodeRSA = require('node-rsa');

// internal modules

const bigIntFromBuf = buf => BigInteger(BigIntegerBuffer.fromBuffer(1, buf).toString());
const bufFromBigInt = bigInt => BigIntegerBuffer.fromString(bigInt.toString(10), 10).toBuffer();

/**
 * splits the input buffer into the encoded components that are required to compute a whole RSA private key
 * @param {Buffer} inputBuffer a Buffer containing the decrypted contents from `com.ibm.websphere.ltpa.PrivateKey
 * @returns {[Buffer]} an array(8) of buffers containing the extracted RSA Key components ([modulus, d, e, p, q, dmp1, dmq1, coeff])
 */
const LTPAPrivKeyToComponentBuffers = (inputBuffer) => {
  const eLength = 3;
  const pLength = 65;
  const qLength = 65;

  const components = Array(8).fill(null);

  components[2] = Buffer.alloc(eLength);
  components[3] = Buffer.alloc(pLength);
  components[4] = Buffer.alloc(qLength);

  // const components = {
  //   n: null,
  //   e: Buffer.alloc(eLength),
  //   d: null,
  //   p: Buffer.alloc(pLength),
  //   q: Buffer.alloc(qLength),
  //   dmp1: null,
  //   dmq1: null,
  //   coeff: null,
  // };

  if (inputBuffer.length > eLength + pLength + qLength) {
    const abyte2 = Buffer.alloc(4);
    inputBuffer.copy(abyte2, 0, 0, 4);
    const privExponentLength = abyte2.readUIntBE(0, 4);

    // privateExponent
    components[1] = Buffer.alloc(privExponentLength);

    inputBuffer.copy(components[1], 0, 4, 4 + privExponentLength);
    inputBuffer.copy(components[2], 0, 4 + privExponentLength, 4 + privExponentLength + eLength);
    inputBuffer.copy(components[3], 0, 4 + privExponentLength + eLength, 4 + privExponentLength + eLength + pLength);
    inputBuffer.copy(
      components[4],
      0,
      4 + privExponentLength + eLength + pLength,
      4 + privExponentLength + eLength + pLength + qLength
    );
  } else {
    inputBuffer.copy(components[2], 0, 0, eLength);
    inputBuffer.copy(components[3], 0, eLength, eLength + pLength);
    inputBuffer.copy(components[4], 0, eLength + pLength, eLength + pLength + qLength);
  }

  return components;
};

// RSAPrivateKey ::= SEQUENCE {
//   version           Version,
//   modulus           INTEGER,  -- n
//   publicExponent    INTEGER,  -- e
//   privateExponent   INTEGER,  -- d
//   prime1            INTEGER,  -- p
//   prime2            INTEGER,  -- q
//   exponent1         INTEGER,  -- d mod (p-1)
//   exponent2         INTEGER,  -- d mod (q-1)
//   coefficient       INTEGER,  -- (inverse of q) mod p
//   otherPrimeInfos   OtherPrimeInfos OPTIONAL
// }
const compileMissingRSAComponents = (components) => {
  // convert all buffers to BigInteger instances
  const abiginteger = components.map(val => (Buffer.isBuffer(val) && bigIntFromBuf(val)) || null);

  // when p < q switch p and q as well as dmp1 and dmq1; force coeff null
  if (abiginteger[3].compareTo(abiginteger[4]) < 0) {
    /* eslint-disable prefer-destructuring */
    let biginteger = abiginteger[3];
    abiginteger[3] = abiginteger[4];
    abiginteger[4] = biginteger;
    biginteger = abiginteger[5];
    abiginteger[5] = abiginteger[6];
    abiginteger[6] = biginteger;
    abiginteger[7] = null;
    /* eslint-enable prefer-destructuring */
  }

  if (abiginteger[7] == null) {
    abiginteger[7] = abiginteger[4].modInv(abiginteger[3]);
  }
  if (abiginteger[0] == null) {
    abiginteger[0] = abiginteger[3].multiply(abiginteger[4]);
  }
  if (abiginteger[1] == null) {
    const pSub1 = abiginteger[3].subtract(BigInteger.one);
    const qSub1 = abiginteger[4].subtract(BigInteger.one);
    abiginteger[1] = abiginteger[2].modInv(pSub1.multiply(qSub1));
  }
  if (abiginteger[5] == null) {
    abiginteger[5] = abiginteger[1].remainder(abiginteger[3].subtract(BigInteger.one));
  }
  if (abiginteger[6] == null) {
    abiginteger[6] = abiginteger[1].remainder(abiginteger[4].subtract(BigInteger.one));
  }

  return abiginteger.map(val => bufFromBigInt(val));
};

const bufferToKeyComponents = buffer => compileMissingRSAComponents(LTPAPrivKeyToComponentBuffers(buffer));

const bufferToRSA = (buffer, params = {}) => {
  const options = Object.assign({ environment: 'node', encryptionScheme: 'pkcs1', signingScheme: 'sha1' }, params);
  const rsaKeyComponents = bufferToKeyComponents(buffer);

  const [n, d, e, p, q, dmp1, dmq1, coeff] = rsaKeyComponents;

  const rsa = NodeRSA({ b: 1024 }); // both versions of LTPATokens only use 1042 bit encryption
  rsa.setOptions(options);
  rsa.importKey(
    {
      n,
      e,
      d,
      p,
      q,
      dmp1,
      dmq1,
      coeff,
    },
    'components'
  );

  return rsa;
};

const bufferToRSAPrivateKeyPEM = buffer => bufferToRSA(buffer).exportKey('private');

module.exports = { bufferToKeyComponents, bufferToRSA, bufferToRSAPrivateKeyPEM };
