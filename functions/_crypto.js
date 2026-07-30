// ============================================================
// NeoKr - Shared Crypto Utilities for Cloudflare Pages Functions
// ============================================================

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ========== Response Helpers ==========

export function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

export function errorResponse(msg, status = 400) {
  return jsonResponse({ error: msg }, status);
}

// ========== Binary Helpers ==========

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(new Uint8Array(bytes)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function bytesToBase64(bytes) {
  const arr = new Uint8Array(bytes);
  let bin = '';
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin);
}

// ========== PKCS7 Padding ==========

function pkcs7Pad(data, blockSize) {
  const padding = blockSize - (data.length % blockSize);
  const padded = new Uint8Array(data.length + padding);
  padded.set(data);
  padded.fill(padding, data.length);
  return padded;
}

function pkcs7Unpad(data) {
  if (data.length === 0) throw new Error('数据为空');
  const padding = data[data.length - 1];
  if (padding === 0 || padding > 16 || padding > data.length) throw new Error('无效的填充');
  for (let i = data.length - padding; i < data.length; i++) {
    if (data[i] !== padding) throw new Error('填充验证失败，请检查密钥和IV是否正确');
  }
  return data.slice(0, data.length - padding);
}

// ========== Key/IV Helpers ==========

function padKey(keyStr, size) {
  const bytes = encoder.encode(keyStr);
  if (bytes.length >= size) return bytes.slice(0, size);
  const padded = new Uint8Array(size);
  padded.set(bytes);
  return padded;
}

function getIV(ivStr, size) {
  if (!ivStr) return new Uint8Array(size);
  const bytes = encoder.encode(ivStr);
  if (bytes.length >= size) return bytes.slice(0, size);
  const padded = new Uint8Array(size);
  padded.set(bytes);
  return padded;
}

// ========== AES ==========

async function aesCbcEncrypt(keyBytes, iv, plainBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['encrypt']);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, plainBytes);
  return new Uint8Array(ciphertext);
}

async function aesCbcDecrypt(keyBytes, iv, cipherBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, cipherBytes);
  return new Uint8Array(plaintext);
}

async function aesEcbEncrypt(keyBytes, plainBytes) {
  const blockSize = 16;
  const padded = pkcs7Pad(plainBytes, blockSize);
  const result = new Uint8Array(padded.length);
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['encrypt']);
  const zeroIV = new Uint8Array(blockSize);
  for (let i = 0; i < padded.length; i += blockSize) {
    const block = padded.slice(i, i + blockSize);
    const enc = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: zeroIV }, key, block));
    result.set(enc, i);
  }
  return result;
}

async function aesEcbDecrypt(keyBytes, cipherBytes) {
  const blockSize = 16;
  if (cipherBytes.length % blockSize !== 0) throw new Error('密文长度不是块大小的整数倍');
  const result = new Uint8Array(cipherBytes.length);
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['decrypt']);
  const zeroIV = new Uint8Array(blockSize);
  for (let i = 0; i < cipherBytes.length; i += blockSize) {
    const block = cipherBytes.slice(i, i + blockSize);
    const dec = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv: zeroIV }, key, block));
    result.set(dec, i);
  }
  return pkcs7Unpad(result);
}

async function aesCtrCrypt(keyBytes, iv, data) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CTR', length: 64 }, false, ['encrypt']);
  const result = await crypto.subtle.encrypt({ name: 'AES-CTR', counter: iv, length: 64 }, key, data);
  return new Uint8Array(result);
}

async function aesGcmEncrypt(keyBytes, nonce, plainBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  const result = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, plainBytes);
  return new Uint8Array(result);
}

async function aesGcmDecrypt(keyBytes, nonce, cipherBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
  const result = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, cipherBytes);
  return new Uint8Array(result);
}

async function aesEncrypt(plaintext, keyStr, ivStr, mode, keySize) {
  const key = padKey(keyStr, keySize / 8);
  const plainBytes = encoder.encode(plaintext);

  switch (mode) {
    case 'ecb': return aesEcbEncrypt(key, plainBytes);
    case 'cbc': return aesCbcEncrypt(key, getIV(ivStr, 16), plainBytes);
    case 'ctr': return aesCtrCrypt(key, getIV(ivStr, 16), plainBytes);
    case 'gcm': return aesGcmEncrypt(key, getIV(ivStr, 12), plainBytes);
    default: return aesCbcEncrypt(key, getIV(ivStr, 16), plainBytes);
  }
}

async function aesDecrypt(cipherBytes, keyStr, ivStr, mode, keySize) {
  const key = padKey(keyStr, keySize / 8);

  switch (mode) {
    case 'ecb': return aesEcbDecrypt(key, cipherBytes);
    case 'cbc': return aesCbcDecrypt(key, getIV(ivStr, 16), cipherBytes);
    case 'ctr': return aesCtrCrypt(key, getIV(ivStr, 16), cipherBytes);
    case 'gcm': return aesGcmDecrypt(key, getIV(ivStr, 12), cipherBytes);
    default: return aesCbcDecrypt(key, getIV(ivStr, 16), cipherBytes);
  }
}

// ========== DES (Pure JS) ==========

const IP = [
  58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
];

const FP = [
  40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
];

const E = [
  32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
  12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21,
  20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
];

const P = [
  16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
  2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
];

const SBoxes = [
  [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
  [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
  [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
  [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
  [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
  [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
  [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
  [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
];

const PC1 = [
  57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
  59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
  31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
  29, 21, 13, 5, 28, 20, 12, 4
];

const PC2 = [
  14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
  26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
  51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
];

const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

function bit(a, n) { return (a >> n) & 1; }
function setBit(a, n, v) { return v ? a | (1 << n) : a & ~(1 << n); }

function permute(table, block, n) {
  let out = 0;
  for (let i = 0; i < n; i++) {
    const bitVal = (block[(table[i] - 1) >> 5] >>> (31 - ((table[i] - 1) & 31))) & 1;
    out = (out << 1) | bitVal;
  }
  return out;
}

function permuteBlock(table, src, nIn) {
  const dst = new Array(nIn >> 5).fill(0);
  for (let i = 0; i < table.length; i++) {
    const pos = table[i] - 1;
    const srcIdx = pos >> 5;
    const srcBit = 31 - (pos & 31);
    const dstIdx = i >> 5;
    const dstBit = 31 - (i & 31);
    if (((src[srcIdx] >>> srcBit) & 1)) dst[dstIdx] |= (1 << dstBit);
  }
  return dst;
}

function sBoxSub(input48) {
  let output32 = 0;
  for (let i = 0; i < 8; i++) {
    const chunk = (input48 >> (6 * (7 - i))) & 0x3F;
    const row = ((chunk >> 5) << 1) | (chunk & 1);
    const col = (chunk >> 1) & 0x0F;
    output32 = (output32 << 4) | SBoxes[i][row][col];
  }
  return output32 >>> 0;
}

function feistel(r32, subkey48) {
  const expanded = permute(E, [0, r32], 48);
  let xored = expanded ^ subkey48;
  xored >>>= 0;
  const sboxed = sBoxSub(xored);
  return permute(P, [0, sboxed], 32);
}

function generateSubkeys(keyBytes) {
  const key64 = [0, 0];
  for (let i = 0; i < 8; i++) {
    key64[0] = (key64[0] << 8) | keyBytes[i];
    key64[0] >>>= 0;
  }
  const cd = permuteBlock(PC1, key64, 64);
  const subkeys = [];
  let c = (cd[0] >>> 4) & 0x0FFFFFFF;
  let d = ((cd[0] & 0x0F) << 24) | ((cd[1] >>> 8) & 0x0FFFFFFF);

  for (let i = 0; i < 16; i++) {
    c = ((c << SHIFTS[i]) | (c >>> (28 - SHIFTS[i]))) & 0x0FFFFFFF;
    d = ((d << SHIFTS[i]) | (d >>> (28 - SHIFTS[i]))) & 0x0FFFFFFF;
    const cdRound = [c << 4, d << 4];
    cdRound[0] >>>= 0;
    cdRound[1] >>>= 0;
    cdRound[0] = cdRound[0] | ((d >>> 24) & 0x0F);
    cdRound[0] >>>= 0;
    subkeys.push(permute(PC2, cdRound, 48));
  }
  return subkeys;
}

function desProcess(block8, keyBytes, encrypt) {
  const block64 = [0, 0];
  for (let i = 0; i < 8; i++) {
    block64[i >> 2] = (block64[i >> 2] << 8) | block8[i];
    block64[i >> 2] >>>= 0;
  }
  const ip = permuteBlock(IP, block64, 64);
  let left = ip[0];
  let right = ip[1];
  const subkeys = generateSubkeys(keyBytes);

  for (let i = 0; i < 16; i++) {
    const sk = encrypt ? subkeys[i] : subkeys[15 - i];
    const f = feistel(right, sk);
    const newRight = (left ^ f) >>> 0;
    left = right;
    right = newRight;
  }

  const swapped = [right, left];
  const fp = permuteBlock(FP, swapped, 64);
  const result = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    const word = fp[i >> 2];
    result[i] = (word >>> (24 - (i & 3) * 8)) & 0xFF;
  }
  return result;
}

function desEncryptBlock(block8, keyBytes) {
  return desProcess(block8, keyBytes, true);
}

function desDecryptBlock(block8, keyBytes) {
  return desProcess(block8, keyBytes, false);
}

function desEncryptECB(keyBytes, plainBytes) {
  const blockSize = 8;
  const padded = pkcs7Pad(plainBytes, blockSize);
  const result = new Uint8Array(padded.length);
  for (let i = 0; i < padded.length; i += blockSize) {
    const block = padded.slice(i, i + blockSize);
    result.set(desEncryptBlock(block, keyBytes), i);
  }
  return result;
}

function desDecryptECB(keyBytes, cipherBytes) {
  const blockSize = 8;
  if (cipherBytes.length % blockSize !== 0) throw new Error('密文长度不是块大小的整数倍');
  const result = new Uint8Array(cipherBytes.length);
  for (let i = 0; i < cipherBytes.length; i += blockSize) {
    const block = cipherBytes.slice(i, i + blockSize);
    result.set(desDecryptBlock(block, keyBytes), i);
  }
  return pkcs7Unpad(result);
}

function desEncryptCBC(keyBytes, iv, plainBytes) {
  const blockSize = 8;
  const padded = pkcs7Pad(plainBytes, blockSize);
  const result = new Uint8Array(padded.length);
  let prev = iv;
  for (let i = 0; i < padded.length; i += blockSize) {
    const xorBlock = new Uint8Array(blockSize);
    for (let j = 0; j < blockSize; j++) xorBlock[j] = padded[i + j] ^ prev[j];
    const enc = desEncryptBlock(xorBlock, keyBytes);
    result.set(enc, i);
    prev = enc;
  }
  return result;
}

function desDecryptCBC(keyBytes, iv, cipherBytes) {
  const blockSize = 8;
  if (cipherBytes.length % blockSize !== 0) throw new Error('密文长度不是块大小的整数倍');
  const result = new Uint8Array(cipherBytes.length);
  let prev = iv;
  for (let i = 0; i < cipherBytes.length; i += blockSize) {
    const block = cipherBytes.slice(i, i + blockSize);
    const dec = desDecryptBlock(block, keyBytes);
    for (let j = 0; j < blockSize; j++) result[i + j] = dec[j] ^ prev[j];
    prev = block;
  }
  return pkcs7Unpad(result);
}

function desEncrypt(plaintext, keyStr, ivStr) {
  const key = padKey(keyStr, 8);
  const plainBytes = encoder.encode(plaintext);
  if (!ivStr) return desEncryptECB(key, plainBytes);
  return desEncryptCBC(key, padKey(ivStr, 8), plainBytes);
}

function desDecrypt(cipherBytes, keyStr, ivStr) {
  const key = padKey(keyStr, 8);
  if (!ivStr) return desDecryptECB(key, cipherBytes);
  return desDecryptCBC(key, padKey(ivStr, 8), cipherBytes);
}

// ========== 3DES ==========

function tripleDesProcess(data, key24Bytes, encrypt) {
  const blockSize = 8;
  const result = new Uint8Array(data.length);
  const k1 = key24Bytes.slice(0, 8);
  const k2 = key24Bytes.slice(8, 16);
  const k3 = key24Bytes.slice(16, 24);

  for (let i = 0; i < data.length; i += blockSize) {
    let block = data.slice(i, i + blockSize);
    if (encrypt) {
      block = desEncryptBlock(block, k1);
      block = desDecryptBlock(block, k2);
      block = desEncryptBlock(block, k3);
    } else {
      block = desDecryptBlock(block, k3);
      block = desEncryptBlock(block, k2);
      block = desDecryptBlock(block, k1);
    }
    result.set(block, i);
  }
  return result;
}

function tripleDesEncryptECB(key24, plainBytes) {
  const padded = pkcs7Pad(plainBytes, 8);
  return tripleDesProcess(padded, key24, true);
}

function tripleDesDecryptECB(key24, cipherBytes) {
  if (cipherBytes.length % 8 !== 0) throw new Error('密文长度不是块大小的整数倍');
  const result = tripleDesProcess(cipherBytes, key24, false);
  return pkcs7Unpad(result);
}

function tripleDesEncryptCBC(key24, iv, plainBytes) {
  const blockSize = 8;
  const padded = pkcs7Pad(plainBytes, blockSize);
  const result = new Uint8Array(padded.length);
  let prev = iv;
  for (let i = 0; i < padded.length; i += blockSize) {
    const xorBlock = new Uint8Array(blockSize);
    for (let j = 0; j < blockSize; j++) xorBlock[j] = padded[i + j] ^ prev[j];
    const enc = tripleDesProcess(xorBlock, key24, true);
    result.set(enc, i);
    prev = enc;
  }
  return result;
}

function tripleDesDecryptCBC(key24, iv, cipherBytes) {
  const blockSize = 8;
  if (cipherBytes.length % blockSize !== 0) throw new Error('密文长度不是块大小的整数倍');
  const result = new Uint8Array(cipherBytes.length);
  let prev = iv;
  for (let i = 0; i < cipherBytes.length; i += blockSize) {
    const block = cipherBytes.slice(i, i + blockSize);
    const dec = tripleDesProcess(block, key24, false);
    for (let j = 0; j < blockSize; j++) result[i + j] = dec[j] ^ prev[j];
    prev = block;
  }
  return pkcs7Unpad(result);
}

function tripleDesEncrypt(plaintext, keyStr, ivStr) {
  const key = padKey(keyStr, 24);
  const plainBytes = encoder.encode(plaintext);
  if (!ivStr) return tripleDesEncryptECB(key, plainBytes);
  return tripleDesEncryptCBC(key, padKey(ivStr, 8), plainBytes);
}

function tripleDesDecrypt(cipherBytes, keyStr, ivStr) {
  const key = padKey(keyStr, 24);
  if (!ivStr) return tripleDesDecryptECB(key, cipherBytes);
  return tripleDesDecryptCBC(key, padKey(ivStr, 8), cipherBytes);
}

// ========== Hash ==========

// MD5 - Pure JS implementation (RFC 1321)
function md5(string) {
  function rotateLeft(x, n) { return (x << n) | (x >>> (32 - n)); }
  function addUnsigned(a, b) {
    const lsw = (a & 0xFFFF) + (b & 0xFFFF);
    const msw = (a >> 16) + (b >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xFFFF);
  }
  function f(q, a, b, x, s, t) { return addUnsigned(rotateLeft(addUnsigned(addUnsigned(a, q), addUnsigned(x, t)), s), b); }
  function ff(a, b, c, d, x, s, t) { return f((b & c) | ((~b) & d), a, b, x, s, t); }
  function gg(a, b, c, d, x, s, t) { return f((b & d) | (c & (~d)), a, b, x, s, t); }
  function hh(a, b, c, d, x, s, t) { return f(b ^ c ^ d, a, b, x, s, t); }
  function ii(a, b, c, d, x, s, t) { return f(c ^ (b | (~d)), a, b, x, s, t); }

  const bytes = encoder.encode(string);
  const msgLen = bytes.length;
  const numBlocks = ((msgLen + 8) >> 6) + 1;
  const totalLen = numBlocks << 6;
  const padded = new Uint8Array(totalLen);
  padded.set(bytes);
  padded[msgLen] = 0x80;
  const words = new Uint32Array(padded.buffer);
  words[(totalLen >> 2) - 2] = msgLen << 3;
  words[(totalLen >> 2) - 1] = (msgLen >>> 29);

  let a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;
  for (let i = 0; i < numBlocks; i++) {
    const x = new Uint32Array(padded.buffer, i * 64, 16);
    let aa = a, bb = b, cc = c, dd = d;
    a = ff(a, b, c, d, x[0], 7, 0xD76AA478); d = ff(d, a, b, c, x[1], 12, 0xE8C7B756);
    c = ff(c, d, a, b, x[2], 17, 0x242070DB); b = ff(b, c, d, a, x[3], 22, 0xC1BDCEEE);
    a = ff(a, b, c, d, x[4], 7, 0xF57C0FAF); d = ff(d, a, b, c, x[5], 12, 0x4787C62A);
    c = ff(c, d, a, b, x[6], 17, 0xA8304613); b = ff(b, c, d, a, x[7], 22, 0xFD469501);
    a = ff(a, b, c, d, x[8], 7, 0x698098D8); d = ff(d, a, b, c, x[9], 12, 0x8B44F7AF);
    c = ff(c, d, a, b, x[10], 17, 0xFFFF5BB1); b = ff(b, c, d, a, x[11], 22, 0x895CD7BE);
    a = ff(a, b, c, d, x[12], 7, 0x6B901122); d = ff(d, a, b, c, x[13], 12, 0xFD987193);
    c = ff(c, d, a, b, x[14], 17, 0xA679438E); b = ff(b, c, d, a, x[15], 22, 0x49B40821);
    a = gg(a, b, c, d, x[1], 5, 0xF61E2562); d = gg(d, a, b, c, x[6], 9, 0xC040B340);
    c = gg(c, d, a, b, x[11], 14, 0x265E5A51); b = gg(b, c, d, a, x[0], 20, 0xE9B6C7AA);
    a = gg(a, b, c, d, x[5], 5, 0xD62F105D); d = gg(d, a, b, c, x[10], 9, 0x2441453);
    c = gg(c, d, a, b, x[15], 14, 0xD8A1E681); b = gg(b, c, d, a, x[4], 20, 0xE7D3FBC8);
    a = gg(a, b, c, d, x[9], 5, 0x21E1CDE6); d = gg(d, a, b, c, x[14], 9, 0xC33707D6);
    c = gg(c, d, a, b, x[3], 14, 0xF4D50D87); b = gg(b, c, d, a, x[8], 20, 0x455A14ED);
    a = gg(a, b, c, d, x[13], 5, 0xA9E3E905); d = gg(d, a, b, c, x[2], 9, 0xFCEFA3F8);
    c = gg(c, d, a, b, x[7], 14, 0x676F02D9); b = gg(b, c, d, a, x[12], 20, 0x8D2A4C8A);
    a = hh(a, b, c, d, x[5], 4, 0xFFFA3942); d = hh(d, a, b, c, x[8], 11, 0x8771F681);
    c = hh(c, d, a, b, x[11], 16, 0x6D9D6122); b = hh(b, c, d, a, x[14], 23, 0xFDE5380C);
    a = hh(a, b, c, d, x[1], 4, 0xA4BEEA44); d = hh(d, a, b, c, x[4], 11, 0x4BDECFA9);
    c = hh(c, d, a, b, x[7], 16, 0xF6BB4B60); b = hh(b, c, d, a, x[10], 23, 0xBEBFBC70);
    a = hh(a, b, c, d, x[13], 4, 0x289B7EC6); d = hh(d, a, b, c, x[0], 11, 0xEAA127FA);
    c = hh(c, d, a, b, x[3], 16, 0xD4EF3085); b = hh(b, c, d, a, x[6], 23, 0x4881D05);
    a = hh(a, b, c, d, x[9], 4, 0xD9D4D039); d = hh(d, a, b, c, x[12], 11, 0xE6DB99E5);
    c = hh(c, d, a, b, x[15], 16, 0x1FA27CF8); b = hh(b, c, d, a, x[2], 23, 0xC4AC5665);
    a = ii(a, b, c, d, x[0], 6, 0xF4292244); d = ii(d, a, b, c, x[7], 10, 0x432AFF97);
    c = ii(c, d, a, b, x[14], 15, 0xAB9423A7); b = ii(b, c, d, a, x[5], 21, 0xFC93A039);
    a = ii(a, b, c, d, x[12], 6, 0x655B59C3); d = ii(d, a, b, c, x[3], 10, 0x8F0CCC92);
    c = ii(c, d, a, b, x[10], 15, 0xFFEFF47D); b = ii(b, c, d, a, x[1], 21, 0x85845DD1);
    a = ii(a, b, c, d, x[8], 6, 0x6FA87E4F); d = ii(d, a, b, c, x[15], 10, 0xFE2CE6E0);
    c = ii(c, d, a, b, x[6], 15, 0xA3014314); b = ii(b, c, d, a, x[13], 21, 0x4E0811A1);
    a = ii(a, b, c, d, x[4], 6, 0xF7537E82); d = ii(d, a, b, c, x[11], 10, 0xBD3AF235);
    c = ii(c, d, a, b, x[2], 15, 0x2AD7D2BB); b = ii(b, c, d, a, x[9], 21, 0xEB86D391);
    a = addUnsigned(a, aa); b = addUnsigned(b, bb); c = addUnsigned(c, cc); d = addUnsigned(d, dd);
  }

  const result = new Uint8Array(16);
  const final = [a, b, c, d];
  for (let i = 0; i < 16; i++) {
    result[i] = (final[i >> 2] >>> ((i & 3) * 8)) & 0xFF;
  }
  return bytesToHex(result);
}

async function shaHash(algo, data) {
  const bytes = encoder.encode(data);
  const hash = await crypto.subtle.digest(algo, bytes);
  return bytesToHex(new Uint8Array(hash));
}

async function hashData(algorithm, data) {
  switch (algorithm) {
    case 'md5': return md5(data);
    case 'sha1': return shaHash('SHA-1', data);
    case 'sha256': return shaHash('SHA-256', data);
    case 'sha512': return shaHash('SHA-512', data);
    default: throw new Error('不支持的哈希算法: ' + algorithm);
  }
}

// ========== HMAC ==========

async function hmacData(algorithm, data, keyStr) {
  const keyBytes = encoder.encode(keyStr);
  let hashAlgo;
  switch (algorithm) {
    case 'hmac-sha256': hashAlgo = 'SHA-256'; break;
    case 'hmac-sha512': hashAlgo = 'SHA-512'; break;
    default: throw new Error('不支持的HMAC算法: ' + algorithm);
  }
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: hashAlgo }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return bytesToHex(new Uint8Array(sig));
}

// ========== RSA ==========

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function pemEncode(der, label) {
  const b64 = arrayBufferToBase64(der);
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

function extractDER(pem) {
  const cleaned = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
  return base64ToBytes(cleaned);
}

async function rsaGenerate(keySize) {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: keySize, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt']
  );
  const pubDer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const privDer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  return {
    publicKey: pemEncode(pubDer, 'PUBLIC KEY'),
    privateKey: pemEncode(privDer, 'PRIVATE KEY'),
    keySize: keySize + ' bits',
  };
}

async function rsaEncrypt(data, publicKeyPEM) {
  const der = extractDER(publicKeyPEM);
  const publicKey = await crypto.subtle.importKey('spki', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  const encrypted = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, encoder.encode(data));
  return bytesToBase64(encrypted);
}

async function rsaDecrypt(cipherB64, privateKeyPEM) {
  const der = extractDER(privateKeyPEM);
  let privateKey;
  try {
    privateKey = await crypto.subtle.importKey('pkcs8', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
  } catch {
    throw new Error('私钥格式不支持，请使用本平台生成的 RSA 密钥对');
  }
  const data = base64ToBytes(cipherB64);
  const decrypted = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, data);
  return decoder.decode(decrypted);
}

// ========== Random Generation ==========

function generateRandomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function generateKey(length, format) {
  return generateWithFormat(length, format, 'key');
}

function generateSalt(length, format) {
  return generateWithFormat(length, format, 'salt');
}

function generateIV(length, format) {
  return generateWithFormat(length, format, 'iv');
}

function generateWithFormat(length, format, type) {
  const bytes = generateRandomBytes(length);
  let result;
  if (format === 'base64') {
    result = bytesToBase64(bytes);
  } else {
    result = bytesToHex(bytes);
  }
  return { result, format, length: length + ' bytes', type };
}

// ========== Base64 ==========

function base64Encode(data) {
  return { result: btoa(data) };
}

function base64Decode(data) {
  return { result: atob(data) };
}

// ========== API Handler Wrappers ==========

export async function handleEncrypt(body) {
  const { algorithm, mode, plaintext, key, iv, keySize, encoding } = body;
  if (!plaintext) throw new Error('明文不能为空');
  if (!key) throw new Error('密钥不能为空');

  let rawBytes;
  switch (algorithm) {
    case 'aes':
      rawBytes = await aesEncrypt(plaintext.trim(), key.trim(), (iv || '').trim(), mode, keySize || 128);
      break;
    case 'des':
      rawBytes = desEncrypt(plaintext.trim(), key.trim(), (iv || '').trim());
      break;
    case '3des':
      rawBytes = tripleDesEncrypt(plaintext.trim(), key.trim(), (iv || '').trim());
      break;
    default:
      throw new Error('不支持的加密算法: ' + algorithm);
  }

  const result = encoding === 'hex' ? bytesToHex(rawBytes) : bytesToBase64(rawBytes);
  return { result, encoding: encoding || 'base64' };
}

export async function handleDecrypt(body) {
  const { algorithm, mode, ciphertext, key, iv, keySize, encoding } = body;
  if (!ciphertext) throw new Error('密文不能为空');
  if (!key) throw new Error('密钥不能为空');

  let rawBytes;
  try {
    rawBytes = encoding === 'hex' ? hexToBytes(ciphertext.trim()) : base64ToBytes(ciphertext.trim());
  } catch {
    throw new Error('密文解码失败');
  }

  let plainBytes;
  switch (algorithm) {
    case 'aes':
      plainBytes = await aesDecrypt(rawBytes, key.trim(), (iv || '').trim(), mode, keySize || 128);
      break;
    case 'des':
      plainBytes = desDecrypt(rawBytes, key.trim(), (iv || '').trim());
      break;
    case '3des':
      plainBytes = tripleDesDecrypt(rawBytes, key.trim(), (iv || '').trim());
      break;
    default:
      throw new Error('不支持的解密算法: ' + algorithm);
  }

  return { result: decoder.decode(plainBytes) };
}

export async function handleHash(body) {
  const { algorithm, data } = body;
  if (!data) throw new Error('数据不能为空');
  const result = await hashData(algorithm, data);
  return { result, algorithm };
}

export async function handleHMAC(body) {
  const { algorithm, data, key } = body;
  if (!data) throw new Error('数据不能为空');
  if (!key) throw new Error('密钥不能为空');
  const result = await hmacData(algorithm, data, key);
  return { result, algorithm };
}

export function handleGenerateKey(body) {
  const { length, format } = body;
  return generateKey(length || 32, format || 'hex');
}

export function handleGenerateSalt(body) {
  const { length, format } = body;
  return generateSalt(length || 16, format || 'hex');
}

export function handleGenerateIV(body) {
  const { length, format } = body;
  return generateIV(length || 16, format || 'hex');
}

export function handleBase64Encode(body) {
  return base64Encode(body.data || '');
}

export function handleBase64Decode(body) {
  try {
    return base64Decode(body.data || '');
  } catch {
    throw new Error('Base64解码失败');
  }
}

export async function handleRSAGenerate(body) {
  const keySize = body.keySize || 2048;
  return rsaGenerate(keySize);
}

export async function handleRSAEncrypt(body) {
  const { data, publicKey } = body;
  if (!data || !publicKey) throw new Error('公钥和数据不能为空');
  const result = await rsaEncrypt(data, publicKey);
  return { result };
}

export async function handleRSADecrypt(body) {
  const { data, privateKey } = body;
  if (!data || !privateKey) throw new Error('私钥和数据不能为空');
  const result = await rsaDecrypt(data, privateKey);
  return { result };
}
