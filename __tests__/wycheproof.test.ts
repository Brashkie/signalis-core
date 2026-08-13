/**
 * Wycheproof known-answer tests for the AEAD primitives.
 *
 * Wycheproof (https://github.com/C2SP/wycheproof, Apache-2.0) is Google's suite
 * of *adversarial* crypto test vectors — it deliberately includes malformed and
 * edge-case inputs (flipped tag bits, Poly1305 edge cases, boundary
 * ciphertexts) that plain round-trip tests never exercise.
 *
 * The committed fixtures under ./vectors are the subset of the official vectors
 * that match this library's supported parameters (256-bit key, 96-bit nonce,
 * 128-bit tag). Each vector is checked in both directions:
 *   - `valid`   → encrypt(msg) must equal ct‖tag AND decrypt(ct‖tag) must equal msg
 *   - `invalid` → decrypt(ct‖tag) must throw (tamper/authentication failure)
 *   - `acceptable` → treated as valid here (all such cases in the filtered set
 *      are standard AEAD inputs)
 */

import { describe, it, expect } from 'vitest';

import { AES_GCM, ChaCha20Poly1305 } from '../src';
import aesVectors from './vectors/aes_gcm_wycheproof.json';
import chachaVectors from './vectors/chacha20_poly1305_wycheproof.json';

interface WycheproofTest {
  tcId: number;
  comment: string;
  key: string;
  iv: string;
  aad: string;
  msg: string;
  ct: string;
  tag: string;
  result: 'valid' | 'invalid' | 'acceptable';
  flags: string[];
}

interface Aead {
  encryptWithAad(key: Buffer, nonce: Buffer, plaintext: Buffer, aad: Buffer): Buffer;
  decryptWithAad(key: Buffer, nonce: Buffer, ciphertext: Buffer, aad: Buffer): Buffer;
}

const hex = (s: string) => Buffer.from(s, 'hex');

function runSuite(name: string, aead: Aead, fixture: { count: number; tests: WycheproofTest[] }) {
  describe(`Wycheproof: ${name}`, () => {
    it(`has the expected number of curated vectors (${fixture.count})`, () => {
      expect(fixture.tests.length).toBe(fixture.count);
    });

    for (const t of fixture.tests) {
      const label = `#${t.tcId} [${t.result}] ${t.comment}`.slice(0, 90);

      it(label, () => {
        const key = hex(t.key);
        const iv = hex(t.iv);
        const aad = hex(t.aad);
        const msg = hex(t.msg);
        const ctTag = Buffer.concat([hex(t.ct), hex(t.tag)]);

        if (t.result === 'invalid') {
          // Authentication must fail — decryption throws.
          expect(() => aead.decryptWithAad(key, iv, ctTag, aad)).toThrow();
        } else {
          // valid / acceptable: encryption reproduces ct‖tag and decryption round-trips.
          const produced = aead.encryptWithAad(key, iv, msg, aad);
          expect(produced.toString('hex')).toBe(ctTag.toString('hex'));

          const recovered = aead.decryptWithAad(key, iv, ctTag, aad);
          expect(recovered.equals(msg)).toBe(true);
        }
      });
    }
  });
}

runSuite('AES-256-GCM', AES_GCM as unknown as Aead, aesVectors as { count: number; tests: WycheproofTest[] });
runSuite(
  'ChaCha20-Poly1305',
  ChaCha20Poly1305 as unknown as Aead,
  chachaVectors as { count: number; tests: WycheproofTest[] },
);
