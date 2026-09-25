'use strict';

/**
 * Envelope encryption for secrets at rest.
 *
 * Each secret gets a fresh random 256-bit data-encryption key (DEK).
 * The DEK encrypts the plaintext with AES-256-GCM (random 12-byte IV).
 * The DEK itself is wrapped with the master KEK (MASTER_KEK env,
 * 32 bytes base64) using AES-256-GCM with its own random IV.
 *
 * Stored format (single text column):
 *   v1.<wrapIv>.<wrappedDek>.<wrapTag>.<dataIv>.<ciphertext>.<dataTag>
 * all segments base64. KEK rotation only requires re-wrapping DEKs
 * (see README "Rotating MASTER_KEK").
 */

const crypto = require('crypto');
const { config } = require('../config');

function kek() {
  const buf = Buffer.from(config.masterKek, 'base64');
  if (buf.length !== 32) throw new Error('MASTER_KEK must be 32 bytes base64');
  return buf;
}

function previousKek() {
  if (!config.masterKekPrevious) return null;
  const buf = Buffer.from(config.masterKekPrevious, 'base64');
  if (buf.length !== 32) throw new Error('MASTER_KEK_PREVIOUS must be 32 bytes base64');
  return buf;
}

function gcmEncrypt(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv, ct, tag: cipher.getAuthTag() };
}

function gcmDecrypt(key, iv, ct, tag) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

/** Encrypt a UTF-8 string (or Buffer). Returns the storable text token. */
function encrypt(plaintext) {
  const data = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), 'utf8');
  const dek = crypto.randomBytes(32);
  const wrapped = gcmEncrypt(kek(), dek);
  const sealed = gcmEncrypt(dek, data);
  dek.fill(0);
  return [
    'v1',
    wrapped.iv.toString('base64'),
    wrapped.ct.toString('base64'),
    wrapped.tag.toString('base64'),
    sealed.iv.toString('base64'),
    sealed.ct.toString('base64'),
    sealed.tag.toString('base64'),
  ].join('.');
}

function unwrapDek(parts, key) {
  return gcmDecrypt(
    key,
    Buffer.from(parts[1], 'base64'),
    Buffer.from(parts[2], 'base64'),
    Buffer.from(parts[3], 'base64')
  );
}

/** Decrypt a token produced by encrypt(). Returns a UTF-8 string. */
function decrypt(token) {
  const parts = String(token).split('.');
  if (parts.length !== 7 || parts[0] !== 'v1') throw new Error('Malformed ciphertext token');
  let dek;
  try {
    dek = unwrapDek(parts, kek());
  } catch (err) {
    const prev = previousKek();
    if (!prev) throw err;
    dek = unwrapDek(parts, prev); // rotation window: old KEK still readable
  }
  try {
    return gcmDecrypt(
      dek,
      Buffer.from(parts[4], 'base64'),
      Buffer.from(parts[5], 'base64'),
      Buffer.from(parts[6], 'base64')
    ).toString('utf8');
  } finally {
    dek.fill(0);
  }
}

/** Re-wrap a token under the current KEK (used by the rotation script). */
function rewrap(token) {
  return encrypt(decrypt(token));
}

module.exports = { encrypt, decrypt, rewrap };
