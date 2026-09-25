'use strict';

/**
 * Minimal authoritative UDP DNS responder for the CNAME-delegation zone
 * (ACME_DNS_ZONE). Answers TXT queries for <subdomain>.<zone> from the
 * acme_dns_records table, plus SOA/NS/A at the apex so delegation works.
 *
 * Production alternative: run an acme-dns instance instead and point the
 * plugin at it — see README "CNAME delegation zone setup".
 */

const dgram = require('dgram');
const { query } = require('../../db/pool');
const { config } = require('../../config');

const QTYPE = { A: 1, NS: 2, SOA: 6, TXT: 16 };

function readName(buf, offset) {
  const labels = [];
  let jumped = false, jumps = 0, pos = offset, end = offset;
  for (;;) {
    if (pos >= buf.length || jumps > 8) break;
    const len = buf[pos];
    if (len === 0) { if (!jumped) end = pos + 1; break; }
    if ((len & 0xc0) === 0xc0) {
      if (!jumped) end = pos + 2;
      pos = ((len & 0x3f) << 8) | buf[pos + 1];
      jumped = true; jumps++;
      continue;
    }
    labels.push(buf.slice(pos + 1, pos + 1 + len).toString('ascii'));
    pos += len + 1;
  }
  return { name: labels.join('.').toLowerCase(), end };
}

function encodeName(name) {
  const parts = name.replace(/\.$/, '').split('.').filter(Boolean);
  const bufs = parts.map((p) => Buffer.concat([Buffer.from([p.length]), Buffer.from(p, 'ascii')]));
  return Buffer.concat([...bufs, Buffer.from([0])]);
}

function answer(nameptr, type, rdata, ttl = 60) {
  const head = Buffer.alloc(10);
  head.writeUInt16BE(type, 0);
  head.writeUInt16BE(1, 2); // IN
  head.writeUInt32BE(ttl, 4);
  head.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([nameptr, head, rdata]);
}

function txtRdata(value) {
  const chunks = [];
  let v = Buffer.from(value, 'utf8');
  while (v.length > 0) {
    const part = v.slice(0, 255);
    chunks.push(Buffer.from([part.length]), part);
    v = v.slice(255);
  }
  return Buffer.concat(chunks);
}

function soaRdata() {
  const mname = encodeName('ns1.' + config.acmeDns.zone);
  const rname = encodeName('hostmaster.' + config.acmeDns.zone);
  const nums = Buffer.alloc(20);
  nums.writeUInt32BE(Math.floor(Date.now() / 1000) % 2 ** 31, 0); // serial
  nums.writeUInt32BE(3600, 4); nums.writeUInt32BE(600, 8);
  nums.writeUInt32BE(604800, 12); nums.writeUInt32BE(60, 16);
  return Buffer.concat([mname, rname, nums]);
}

async function buildResponse(msg) {
  if (msg.length < 12) return null;
  const id = msg.readUInt16BE(0);
  const qdcount = msg.readUInt16BE(4);
  if (qdcount < 1) return null;
  const { name, end } = readName(msg, 12);
  if (msg.length < end + 4) return null;
  const qtype = msg.readUInt16BE(end);
  const question = msg.slice(12, end + 4);
  const zone = config.acmeDns.zone;

  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  const nameptr = Buffer.from([0xc0, 0x0c]);

  const inZone = name === zone || name.endsWith('.' + zone);
  let answers = [];
  let rcode = 0;

  if (!inZone) {
    rcode = 5; // REFUSED — we are only authoritative for our zone
  } else if (qtype === QTYPE.TXT && name !== zone) {
    const subdomain = name.slice(0, -(zone.length + 1));
    const { rows } = await query('SELECT txt_value FROM acme_dns_records WHERE subdomain = $1 ORDER BY created_at DESC LIMIT 20', [subdomain]);
    answers = rows.map((r) => answer(nameptr, QTYPE.TXT, txtRdata(r.txt_value)));
  } else if (qtype === QTYPE.SOA) {
    answers = [answer(nameptr, QTYPE.SOA, soaRdata(), 300)];
  } else if (qtype === QTYPE.NS && name === zone) {
    answers = [answer(nameptr, QTYPE.NS, encodeName('ns1.' + zone), 3600)];
  } else if (qtype === QTYPE.A && name === 'ns1.' + zone) {
    const ip = config.acmeDns.publicIp.split('.').map((n) => parseInt(n, 10));
    answers = [answer(nameptr, QTYPE.A, Buffer.from(ip), 3600)];
  }

  // flags: QR=1, AA=1, RD copied=0, RCODE
  header.writeUInt16BE(0x8400 | rcode, 2);
  header.writeUInt16BE(1, 4);          // QDCOUNT
  header.writeUInt16BE(answers.length, 6); // ANCOUNT
  return Buffer.concat([header, question, ...answers]);
}

function startAuthDns(port) {
  const socket = dgram.createSocket('udp4');
  socket.on('message', async (msg, rinfo) => {
    try {
      const resp = await buildResponse(msg);
      if (resp) socket.send(resp, rinfo.port, rinfo.address);
    } catch (err) {
      console.error('[acme-dns] responder error:', err.message);
    }
  });
  return new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(port, () => resolve(socket));
  });
}

module.exports = { startAuthDns };
