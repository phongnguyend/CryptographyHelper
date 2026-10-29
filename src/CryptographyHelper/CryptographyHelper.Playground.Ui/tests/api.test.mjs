import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, pbkdf2Sync } from 'node:crypto';
const origin = process.env.API_URL || 'http://localhost:5180';
async function post(path, body, status = 200) {
  const response = await fetch(`${origin}/api/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const data = await response.json();
  assert.equal(response.status, status, JSON.stringify(data));
  return data;
}
test('hashes and HMAC match independent known implementations', async () => {
  for (const algorithm of ['MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512']) {
    const plain = await post('hash', { input: 'abc', algorithm });
    assert.equal(plain.hex, createHash(algorithm.toLowerCase()).update('abc').digest('hex').toUpperCase());
    const mac = await post('hash', { input: 'abc', algorithm, hmac: true, key: 'key' });
    assert.equal(mac.base64, createHmac(algorithm.toLowerCase(), 'key').update('abc').digest('base64'));
  }
  assert.equal((await post('hash', { input: '616263', encoding: 'Hex' })).hex, (await post('hash', { input: 'YWJj', encoding: 'Base64' })).hex);
});
test('PBKDF2 matches independent implementation', async () => {
  const result = await post('pbkdf2', { password: 'password', salt: 'c2FsdHNhbHQ=', iterations: 1000, length: 32 });
  assert.equal(result.base64, pbkdf2Sync('password', 'saltsalt', 1000, 32, 'sha256').toString('base64'));
});
test('all symmetric algorithms round trip Unicode', async () => {
  for (const algorithm of ['AES', 'DES', 'TripleDES']) {
    const key = (await post('random', { length: algorithm === 'AES' ? 32 : algorithm === 'DES' ? 8 : 24 })).base64;
    const iv = (await post('random', { length: algorithm === 'AES' ? 16 : 8 })).base64;
    for (const mode of ['CBC', 'ECB']) {
      const options = { algorithm, key, iv, mode };
      const encrypted = await post('symmetric', { ...options, input: 'Hello ??' });
      const decrypted = await post('symmetric', { ...options, input: encrypted.base64, operation: 'decrypt' });
      assert.equal(decrypted.text, 'Hello ??');
    }
  }
});
test('RSA XML and PEM encrypt, decrypt, sign and detect tampering', async () => {
  for (const format of ['Xml', 'Pem']) {
    const keys = await post('rsa/keys', { format, size: 2048 });
    const encrypted = await post('rsa', { input: 'hello', key: keys.publicKey, format });
    const decrypted = await post('rsa', { input: encrypted.base64, key: keys.privateKey, format, operation: 'decrypt' });
    assert.equal(decrypted.text, 'hello');
    for (const operation of ['sign', 'signHash']) {
      const input = operation === 'sign' ? 'hello' : createHash('sha256').update('hello').digest('base64');
      const encoding = operation === 'sign' ? 'Text' : 'Base64';
      const signed = await post('rsa', { input, encoding, key: keys.privateKey, format, operation });
      const verify = { input, encoding, key: keys.publicKey, format, operation: operation === 'sign' ? 'verify' : 'verifyHash', signature: signed.base64 };
      assert.equal((await post('rsa', verify)).verified, true);
      assert.equal((await post('rsa', { ...verify, signature: Buffer.alloc(256).toString('base64') })).verified, false);
    }
  }
});
test('invalid user inputs return actionable 400 responses', async () => {
  for (const [path, body] of [
    ['hash', { input: '!', encoding: 'Base64' }], ['hash', { input: 'abc', algorithm: 'unknown' }],
    ['pbkdf2', { password: 'p', salt: 'c2FsdHNhbHQ=', iterations: 1000001 }],
    ['symmetric', { input: 'abc', key: 'YQ==', iv: 'YQ==' }],
    ['rsa', { input: 'abc', key: 'invalid' }], ['rsa/keys', { size: 1024 }], ['random', { length: -1 }],
    ['hash', { input: null }],
  ]) assert.ok((await post(path, body, 400)).detail);
});
