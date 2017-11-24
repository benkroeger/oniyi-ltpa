# oniyi-ltpa
Tools to deal with Lightweight Third-Party Authentication tokens

# Usage

Factory takes two arguments:

* `keyfilePath` - path to the exported ltpa keys from websphere (relative paths will be resolved from `process.cwd()`)
* `password` - the password for `keyfile`

```javascript
const moment = require('moment');
const { ltpa2Factory } = require('oniyi-ltpa');
const { LTPA_PASSWORD } = process.env;

const myLtpaToken2 = 'sMzub9exuSeFniM/ae6U...My0njWl7rFygcs0bL8Y=';

ltpa2Factory('keys.properties', LTPA_PASSWORD, (err, ltpa2) => {
  if (err) {
    // @TODO: better error handling
    throw err;
  }

  // Decode an existing token
  const ltpaToken2Content = ltpa2.decode(ltpaToken2);
  console.log(ltpaToken2Content);
  // output will look similar to this:
  // { body:
  //  { expire: '1511205660000',
  //    host: 'my.websphere.host',
  //    'java.naming.provider.url': 'corbaloc\\:iiop\\:my-websphere-host\\:9811/WsnAdminNameService',
  //    port: '8881',
  //    'process.serverName': 'socialCell01\\:IC5Node01\\:InfraCluster_server1',
  //    'security.authMechOID': 'oid\\:1.3.18.0.2.30.2',
  //    type: 'SOAP',
  //    u: 'user\\:my.ldap.host\\:389/CN=Max Mustermann,OU=ACME-User,dc=ad,dc=acme,dc=com' },
  // expires: 1511535657828,
  // signature: 'o+oVbX3SMKG...J3wDaPi6DIdCNblLF7h2A=' }


  // create new token

  // apply some minor modifications to the previously decoded token (change DN and expires time)
  const content = Object.assign({}, ltpaToken2Content);
  content.body.u = ltpaToken2Content.body.u.replace('Max Mustermann', 'Armin Arm');
  content.expires = moment()
    .add(1, 'hours')
    .valueOf();

  const newLtpaToken = ltpa2.makeToken(content2);
  console.log(newLtpaToken);
  // output will look similar to this:
  // sMzub9exuSeFniM/ae6U...My0njWl7rFygcasdfcdsuoj8709uL8Y=
});
```
