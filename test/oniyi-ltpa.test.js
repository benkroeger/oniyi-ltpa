import test from 'ava';
import { ltpa2Factory } from '../lib';

const { ltpaToken, ltpaToken2 } = require('./fixtures/constants');

const { LTPA_PASSWORD } = process.env;

test.cb('creates ltpa instance from keys.properties file', t => {
  ltpa2Factory('test/fixtures/keys.properties', LTPA_PASSWORD, (err, ltpa2) => {
    t.falsy(err);

    const keyfile = ltpa2.getKeyfile();

    const { creationHost, realm, version, privateKeyPEM } = keyfile;
    t.is(creationHost, 'foo.bar.com');
    t.is(realm, 'foo.bar.com:389');
    t.is(version, 1);
    t.true(privateKeyPEM.startsWith('-----BEGIN RSA PRIVATE KEY-----'));
    t.end();
  });
});

test.cb('decodes ltpaToken', t => {
  ltpa2Factory('test/fixtures/keys.properties', LTPA_PASSWORD, (err, ltpa2) => {
    t.falsy(err);

    const decoded = ltpa2.decodeV1(ltpaToken);

    t.true(decoded.body.u.includes('CN=Benjamin Kroeger'));
    t.is(decoded.expires, '1522221802666');

    t.end();
  });
});

test.cb('decodes ltpaToken2', t => {
  ltpa2Factory('test/fixtures/keys.properties', LTPA_PASSWORD, (err, ltpa2) => {
    t.falsy(err);

    const decoded = ltpa2.decode(ltpaToken2);

    t.true(decoded.body.u.includes('CN=Benjamin Kroeger'));
    t.is(decoded.body.port, '8883');
    t.is(decoded.body.expire, '1522965060000');
    t.is(decoded.body.type, 'SOAP');
    t.is(decoded.body['security.authMechOID'], 'oid\\:1.3.18.0.2.30.2');
    t.is(decoded.expires, '1522965060000');

    t.end();
  });
});
