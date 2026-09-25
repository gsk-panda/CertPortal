'use strict';

// Generates the self-signed TLS cert Pebble serves its HTTPS endpoints with
// (test/certs/localhost/). Committed output; re-run to refresh.

const fs = require('fs');
const path = require('path');
const forge = require('node-forge');

const dir = path.join(__dirname, '..', 'test', 'certs', 'localhost');
fs.mkdirSync(dir, { recursive: true });

const keys = forge.pki.rsa.generateKeyPair(2048);
const cert = forge.pki.createCertificate();
cert.publicKey = keys.publicKey;
cert.serialNumber = '01' + Date.now().toString(16);
cert.validity.notBefore = new Date(Date.now() - 86400e3);
cert.validity.notAfter = new Date(Date.now() + 10 * 365 * 86400e3);
const attrs = [{ name: 'commonName', value: 'localhost' }];
cert.setSubject(attrs);
cert.setIssuer(attrs);
cert.setExtensions([
  { name: 'basicConstraints', cA: false },
  { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
  { name: 'extKeyUsage', serverAuth: true },
  {
    name: 'subjectAltName',
    altNames: [
      { type: 2, value: 'localhost' },
      { type: 2, value: 'pebble' },
      { type: 7, ip: '127.0.0.1' },
    ],
  },
]);
cert.sign(keys.privateKey, forge.md.sha256.create());

fs.writeFileSync(path.join(dir, 'cert.pem'), forge.pki.certificateToPem(cert));
fs.writeFileSync(path.join(dir, 'key.pem'), forge.pki.privateKeyToPem(keys.privateKey));
console.log('wrote', dir);
