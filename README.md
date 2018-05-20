# oniyi-ltpa

> Tools to deal with Lightweight Third-Party Authentication 2 (LTPA2) tokens

## Usage

This package's main module exports a factory function – used to create an instance of LTPA tools that work with your specific LTPA keys and password.

The factory takes two arguments:

* `keyfilePath` - path to `LTPA keys` file (e.g. from IBM WebSphere Application Server). Relative paths are resolved from `process.cwd()`
* `password` - the password for `keyfilePath`

```javascript
const { ltpa2Factory } = require('oniyi-ltpa');
const { LTPA_PASSWORD } = process.env;

ltpa2Factory('/path/to/my/keys.properties', LTPA_PASSWORD, (err, ltpa2Tools) => {
  // handle err
  // or use ltpa2Tools
  // here
});
```

## ltpa2Tools

Since LTPA version 1 and version 2 use different algorithms to cypher and de-cypher the token value, this module now (starting with version 1.1.0) exposes an additional method to decode LTPA version 1 tokens.

Ciphers used:

* LTPA version 1: `'DES-EDE3'`
* LTPA version 2: `'AES-128-CBC'`

### getKeyfile

returns a copy of the `keyfilePath` contents enriched with a `privateKeyPEM` property (holds RSA PEM for private key)

### decode

use this method to decode an existing LTPA2 token (e.g. from a cookie value)

```javascript
// assuming `myLtpaToken2` holds the value of an existing LTPA2 token
const myLtpaToken2 = 'sMzub9exuSeFniM/ae6U...My0njWl7rFygcs0bL8Y=';

ltpa2Factory('keys.properties', LTPA_PASSWORD, (err, ltpa2Tools) => {
  // handle error

  // Decode an existing token
  const ltpaToken2Content = ltpa2Tools.decode(myLtpaToken2);
  // { body:
  //  { expire: '1511205660000',
  //    host: 'my.websphere.host',
  //    'java.naming.provider.url': 'corbaloc\\:iiop\\:my-websphere-host\\:9811/WsnAdminNameService',
  //    port: '8881',
  //    'process.serverName': 'cell01\\:node01\\:cluster01_server01',
  //    'security.authMechOID': 'oid\\:1.3.18.0.2.30.2',
  //    type: 'SOAP',
  //    u: 'user\\:my.ldap.host\\:389/CN=Max Mustermann,OU=ACME-User,dc=ad,dc=acme,dc=com' },
  // expires: 1511535657828,
  // signature: 'o+oVbX3SMKG...J3wDaPi6DIdCNblLF7h2A=' }
});
```

### decodeV1

use this method to decode an existing LTPA1 token (created with the same LTPA keys).

```javascript
// assuming `myLtpaToken` holds the value of an existing LTPA1 token
const myLtpaToken = 'sMzub9exuSeFniM/ae6U...My0njWl7rFygcs0bL8Y=';

ltpa2Factory('keys.properties', LTPA_PASSWORD, (err, ltpa2Tools) => {
  // handle error

  // Decode an existing token
  const ltpaTokenContent = ltpa2Tools.decodeV1(myLtpaToken);
  // {
  //    body:
  //      { u: 'user\\:my.ldap.host\\:389/CN=Max Mustermann,OU=ACME-User,dc=ad,dc=acme,dc=com' },
  //    expires: 1511535657828,
  //    signature: 'o+oVbX3SMKG...J3wDaPi6DIdCNblLF7h2A=',
  // }
});
```

### makeToken

use this method to encode an object into an LTPA2 string value.  
this method takes an object as single argument. object **must** have the properties `body` and `expires`.

```javascript
ltpa2Factory('keys.properties', LTPA_PASSWORD, (err, ltpa2Tools) => {
  // handle error

  const content = {
    body: {
      expire: '1511205660000',
      host: 'my.websphere.host',
      'java.naming.provider.url': 'corbaloc\\:iiop\\:my-websphere-host\\:9811/WsnAdminNameService',
      port: '8881',
      'process.serverName': 'cell01\\:node01\\:cluster01_server01',
      'security.authMechOID': 'oid\\:1.3.18.0.2.30.2',
      type: 'SOAP',
      u: 'user\\:my.ldap.host\\:389/CN=Max Mustermann,OU=ACME-User,dc=ad,dc=acme,dc=com',
    },
    expires: 1511535657828,
  };

  const newLtpaToken = ltpa2Tools.makeToken(content);
  // sMzub9exuSeFniM/ae6U...My0njWl7rFygcasdfcdsuoj8709uL8Y=
});
```

## Under the hood

When the factory is invoked, `oniyi-ltpa` attempts to read the contents of `keyfilePath` and decodes the provided `password` into the actual .
To get to the actual `DES_EDE_3_KEY`, `password` needs to be decoded and used to decrypt the `des3Key` property from `keyfilePath`. Decoding `password` means to `sha1` hash it and right-pad the result with 0*0 bytes to a total length of 24 bytes. Finally, we need to base64 decode `des3Key` and decipher the result with our hashed and padded password. The result can then be used as `DES_EDE_3_KEY` secret for further (de-)crypto actions.
The following abstract formula describes how `des3Key` in our `keyfilePath` was created:

```
base64Encode(crypt(myActualKey, 'DES-EDE3', pad(sha1(password), 24)))
```

The same procedure is then repeated for the `privateKey` property from `keyfilePath`. The result is a decrypted private key buffer, which `oniyi-ltpa` then transforms into a RSA private key PEM. The RSA PEM is used when `makeToken` gets invoked – and allows us to leverage node.js' native `crypto.createSign()` when signing the contents of an LTPA2 token.
The following abstract formulas describe how signatures are created:

```
LTPA1 BASE64( RSA( SHA_DIGEST( token_body ) ) )
LTPA2 BASE64( SHA1_WITH_RSA( SHA_DIGEST( token_body ) ) )
```

When compiling the RSA from the decrypted private key buffer, `oniyi-ltpa` performs some additional calculations to get to the missing pieces required for RSA. In short, the privateKey from `keyfilePath` only contains the bare minimum of informations, all of them joined into a single value.
So, basically, the private key as a variable length (length is different for each LTPA key). It's built by adding the following bytes to a buffer:

* left-pad (4 bytes) - no use
* private exponent / d (variable size)
* public exponent / e (3 bytes)
* prime1 (65 bytes)
* prime2 (65 bytes)

Having this information at hand, the remaining RSA components can be calculated as follows:

```
RSAPrivateKey ::= SEQUENCE {
  version           Version,
  modulus           INTEGER,  -- n
  publicExponent    INTEGER,  -- e
  privateExponent   INTEGER,  -- d
  prime1            INTEGER,  -- p
  prime2            INTEGER,  -- q
  exponent1         INTEGER,  -- d mod (p-1)
  exponent2         INTEGER,  -- d mod (q-1)
  coefficient       INTEGER,  -- (inverse of q) mod p
  otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
```

All of these computations require to deal with BigInteger variables, which are not natively supported in node.js. Luckily, there are existing packages for this already: [big-integer](https://www.npmjs.com/package/big-integer) and [node-biginteger](https://www.npmjs.com/package/node-biginteger). Unfortunately, `oniyi-ltpa` needs both because one of them can transform from and to buffers and the other has all the computations needed.
