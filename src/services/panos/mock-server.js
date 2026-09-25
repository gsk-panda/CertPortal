'use strict';

/**
 * Mock PAN-OS XML API (MOCK_PANOS=true).
 *
 * Honors: type=keygen, type=op (show system info / jobs / HA state),
 * type=import&category=keypair (multipart), type=config&action=set,
 * type=commit + job polling.
 *
 * It also runs a fake "GlobalProtect portal" TLS listener on port+1.
 * After an imported keypair is committed the listener serves that exact
 * certificate, so CertPortal's post-deploy TLS validation exercises the
 * real code path end-to-end.
 */

const https = require('https');
const tls = require('tls');
const crypto = require('crypto');
const { URL } = require('url');
const forge = require('node-forge');

function makeSelfSigned(cn) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01' + crypto.randomBytes(8).toString('hex');
  cert.validity.notBefore = new Date(Date.now() - 3600e3);
  cert.validity.notAfter = new Date(Date.now() + 365 * 86400e3);
  const attrs = [{ name: 'commonName', value: cn }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return {
    key: forge.pki.privateKeyToPem(keys.privateKey),
    cert: forge.pki.certificateToPem(cert),
  };
}

const state = {
  validKeys: new Set(['MOCKKEY-' + 'static']),
  jobs: new Map(),          // id -> { polls, status }
  nextJob: 1000,
  pendingKeypairs: new Map(), // certName -> { cert, key }
  committedKeypair: null,
  configSets: [],
  dataPlane: null,
};

function xmlOk(inner) { return `<response status="success">${inner || ''}</response>`; }
function xmlErr(msg, code = '403') { return `<response status="error" code="${code}"><result><msg>${msg}</msg></result></response>`; }

function parseMultipartFile(body, contentType) {
  const m = /boundary=(.+)$/.exec(contentType || '');
  if (!m) return null;
  const boundary = '--' + m[1].replace(/^"|"$/g, '');
  const text = body.toString('binary');
  const start = text.indexOf('\r\n\r\n', text.indexOf(boundary));
  if (start === -1) return null;
  const end = text.indexOf(boundary, start);
  if (end === -1) return null;
  return Buffer.from(text.slice(start + 4, end).replace(/\r\n$/, ''), 'binary').toString('utf8');
}

function handleApi(params, body, contentType) {
  const type = params.get('type');

  if (type === 'keygen') {
    const user = params.get('user'), password = params.get('password');
    if (!user || !password || password === 'wrong') return xmlErr('Invalid credentials.', '403');
    const key = 'LUFRPT-MOCK-' + crypto.randomBytes(12).toString('hex');
    state.validKeys.add(key);
    return xmlOk(`<result><key>${key}</key></result>`);
  }

  if (!state.validKeys.has(params.get('key'))) {
    return xmlErr('Invalid API key', '403');
  }

  if (type === 'op') {
    const cmd = params.get('cmd') || '';
    if (cmd.includes('<system><info>')) {
      return xmlOk(`<result><system>
        <hostname>mock-fw-01</hostname>
        <serial>0123456789012</serial>
        <model>PA-VM</model>
        <sw-version>11.1.4-h7</sw-version>
      </system></result>`);
    }
    if (cmd.includes('<high-availability><state>')) {
      return xmlOk('<result><enabled>no</enabled></result>');
    }
    const jm = /<jobs><id>(\d+)<\/id><\/jobs>/.exec(cmd);
    if (jm) {
      const job = state.jobs.get(jm[1]);
      if (!job) return xmlErr(`job ${jm[1]} not found`, '7');
      job.polls += 1;
      const done = job.polls >= 2; // first poll ACT, then FIN
      if (done && !job.finished) {
        job.finished = true;
        // commit activates the most recently imported keypair on the data plane
        if (state.pendingKeypairs.size > 0) {
          const last = [...state.pendingKeypairs.values()].pop();
          state.committedKeypair = last;
          if (state.dataPlane) {
            state.dataPlane.setSecureContext({ key: last.key, cert: last.cert });
          }
        }
      }
      return xmlOk(`<result><job>
        <id>${jm[1]}</id>
        <type>Commit</type>
        <status>${done ? 'FIN' : 'ACT'}</status>
        <result>${done ? 'OK' : 'PEND'}</result>
        <progress>${done ? 100 : 55}</progress>
        <details><line>${done ? 'configuration committed successfully' : 'processing'}</line></details>
      </job></result>`);
    }
    return xmlErr('unsupported op cmd', '7');
  }

  if (type === 'import') {
    if (params.get('category') !== 'keypair') return xmlErr('unsupported import category', '7');
    const name = params.get('certificate-name');
    const passphrase = params.get('passphrase');
    if (!name) return xmlErr('certificate-name required', '7');
    const file = parseMultipartFile(body, contentType);
    if (!file) return xmlErr('missing file', '7');
    // Split PEM blocks: certs + encrypted private key
    const certs = file.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
    const keyPem = (file.match(/-----BEGIN (?:ENCRYPTED PRIVATE KEY|EC PRIVATE KEY|RSA PRIVATE KEY|PRIVATE KEY)-----[\s\S]*?-----END (?:ENCRYPTED PRIVATE KEY|EC PRIVATE KEY|RSA PRIVATE KEY|PRIVATE KEY)-----/) || [])[0];
    if (!certs.length || !keyPem) return xmlErr('file must contain certificate and private key', '7');
    let keyObj;
    try {
      keyObj = crypto.createPrivateKey({ key: keyPem, passphrase: passphrase || undefined });
    } catch (err) {
      return xmlErr('failed to decrypt private key (bad passphrase?)', '7');
    }
    // verify key matches leaf cert
    try {
      const leaf = new crypto.X509Certificate(certs[0]);
      if (!leaf.checkPrivateKey(keyObj)) return xmlErr('key does not match certificate', '7');
    } catch (err) {
      return xmlErr('invalid certificate', '7');
    }
    state.pendingKeypairs.set(name, {
      cert: certs.join('\n'),
      key: keyObj.export({ type: 'pkcs8', format: 'pem' }),
      name,
    });
    return xmlOk(`<result>Successfully imported ${name} into candidate configuration</result>`);
  }

  if (type === 'config' && params.get('action') === 'set') {
    state.configSets.push({ xpath: params.get('xpath'), element: params.get('element') });
    return xmlOk('<msg>command succeeded</msg>');
  }

  if (type === 'commit') {
    const id = String(state.nextJob++);
    state.jobs.set(id, { polls: 0, finished: false });
    return xmlOk(`<result><msg><line>Commit job enqueued with jobid ${id}</line></msg><job>${id}</job></result>`);
  }

  return xmlErr(`unsupported type ${type}`, '7');
}

function startMockPanos(port) {
  const ss = makeSelfSigned('mock-fw-01');

  const apiServer = https.createServer({ key: ss.key, cert: ss.cert }, (req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const url = new URL(req.url, 'https://localhost');
      const params = url.searchParams;
      // params may also arrive form-encoded in the body (keygen POST)
      if ((req.headers['content-type'] || '').includes('x-www-form-urlencoded')) {
        for (const [k, v] of new URLSearchParams(body.toString())) params.set(k, v);
      }
      if (url.pathname !== '/api/' && url.pathname !== '/api') {
        res.writeHead(404); return res.end('not found');
      }
      const xml = handleApi(params, body, req.headers['content-type']);
      res.writeHead(200, { 'content-type': 'application/xml' });
      res.end(xml);
    });
  });

  // fake GP portal: serves the committed cert for post-deploy validation
  const dataPlane = tls.createServer({ key: ss.key, cert: ss.cert }, (socket) => {
    socket.end('HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n');
  });
  state.dataPlane = dataPlane;

  return new Promise((resolve) => {
    apiServer.listen(port, () => {
      dataPlane.listen(port + 1, () => resolve({ apiServer, dataPlane, state }));
    });
  });
}

module.exports = { startMockPanos, _mockState: state };
