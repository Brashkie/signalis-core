import { describe, it, expect } from 'vitest';
import {
  AES_GCM,
  AuthenticationError,
  CryptoError,
  ValidationError,
  secureRandom,
  AES_256_KEY_SIZE,
  AES_256_GCM_NONCE_SIZE,
} from '../src/index';

describe('AES-GCM with AAD (v0.2.0)', () => {
  describe('encryptWithAad / decryptWithAad', () => {
    it('round-trip with AAD', () => {
      const key = secureRandom(AES_256_KEY_SIZE);
      const nonce = secureRandom(AES_256_GCM_NONCE_SIZE);
      const plaintext = Buffer.from('secret message');
      const aad = Buffer.from('message_id=42');

      const ct = AES_GCM.encryptWithAad(key, nonce, plaintext, aad);
      const pt = AES_GCM.decryptWithAad(key, nonce, ct, aad);

      expect(pt.equals(plaintext)).toBe(true);
    });

    it('AAD mismatch fails decryption with AuthenticationError', () => {
      const key = secureRandom(32);
      const nonce = secureRandom(12);

      const ct = AES_GCM.encryptWithAad(
        key,
        nonce,
        Buffer.from('msg'),
        Buffer.from('correct_aad'),
      );

      expect(() =>
        AES_GCM.decryptWithAad(key, nonce, ct, Buffer.from('wrong_aad')),
      ).toThrow(AuthenticationError);
    });

    it('empty AAD works', () => {
      const key = secureRandom(32);
      const nonce = secureRandom(12);

      const ct = AES_GCM.encryptWithAad(
        key,
        nonce,
        Buffer.from('msg'),
        Buffer.alloc(0),
      );
      const pt = AES_GCM.decryptWithAad(key, nonce, ct, Buffer.alloc(0));

      expect(pt.equals(Buffer.from('msg'))).toBe(true);
    });

    it('large AAD works', () => {
      const key = secureRandom(32);
      const nonce = secureRandom(12);
      const aad = Buffer.alloc(10_000, 0xab);

      const ct = AES_GCM.encryptWithAad(key, nonce, Buffer.from('msg'), aad);
      const pt = AES_GCM.decryptWithAad(key, nonce, ct, aad);

      expect(pt.equals(Buffer.from('msg'))).toBe(true);
    });

    it('encrypt without AAD equals encrypt with empty AAD', () => {
      const key = secureRandom(32);
      const nonce = secureRandom(12);

      const ct1 = AES_GCM.encrypt(key, nonce, Buffer.from('msg'));
      const ct2 = AES_GCM.encryptWithAad(
        key,
        nonce,
        Buffer.from('msg'),
        Buffer.alloc(0),
      );

      // With AES-GCM, no AAD == empty AAD
      expect(ct1.equals(ct2)).toBe(true);
    });

    it('tampered ciphertext fails decryption', () => {
      const key = secureRandom(32);
      const nonce = secureRandom(12);
      const aad = Buffer.from('aad');

      const ct = AES_GCM.encryptWithAad(key, nonce, Buffer.from('msg'), aad);
      ct[0]! ^= 0xff;

      expect(() => AES_GCM.decryptWithAad(key, nonce, ct, aad)).toThrow(AuthenticationError);
    });

    it('different keys produce different ciphertexts', () => {
      const key1 = secureRandom(32);
      const key2 = secureRandom(32);
      const nonce = Buffer.alloc(12, 1);
      const aad = Buffer.from('aad');

      const ct1 = AES_GCM.encryptWithAad(key1, nonce, Buffer.from('msg'), aad);
      const ct2 = AES_GCM.encryptWithAad(key2, nonce, Buffer.from('msg'), aad);

      expect(ct1.equals(ct2)).toBe(false);
    });
  });

  describe('input validation', () => {
    it('throws ValidationError on wrong key size', () => {
      expect(() =>
        AES_GCM.encryptWithAad(
          Buffer.alloc(31),
          Buffer.alloc(12),
          Buffer.from('msg'),
          Buffer.alloc(0),
        ),
      ).toThrow(ValidationError);
    });

    it('throws ValidationError on wrong nonce size', () => {
      expect(() =>
        AES_GCM.encryptWithAad(
          Buffer.alloc(32),
          Buffer.alloc(11),
          Buffer.from('msg'),
          Buffer.alloc(0),
        ),
      ).toThrow(ValidationError);
    });

    it('decryptWithAad throws ValidationError on wrong key size', () => {
      expect(() =>
        AES_GCM.decryptWithAad(
          Buffer.alloc(31),
          Buffer.alloc(12),
          Buffer.alloc(32),
          Buffer.alloc(0),
        ),
      ).toThrow(ValidationError);
    });

    it('decryptWithAad throws ValidationError on wrong nonce size', () => {
      expect(() =>
        AES_GCM.decryptWithAad(
          Buffer.alloc(32),
          Buffer.alloc(11),
          Buffer.alloc(32),
          Buffer.alloc(0),
        ),
      ).toThrow(ValidationError);
    });

    it('decryptWithAad throws ValidationError on non-Buffer ciphertext', () => {
      expect(() =>
        AES_GCM.decryptWithAad(
          Buffer.alloc(32),
          Buffer.alloc(12),
          'not a buffer' as any,
          Buffer.alloc(0),
        ),
      ).toThrow(ValidationError);
    });

    it('decryptWithAad throws ValidationError on non-Buffer aad', () => {
      expect(() =>
        AES_GCM.decryptWithAad(
          Buffer.alloc(32),
          Buffer.alloc(12),
          Buffer.alloc(32),
          'not a buffer' as any,
        ),
      ).toThrow(ValidationError);
    });

    it('decryptWithAad throws CryptoError when ciphertext shorter than tag size', () => {
      // This covers the explicit length check (lines 403-407 in core.ts)
      expect(() =>
        AES_GCM.decryptWithAad(
          Buffer.alloc(32),
          Buffer.alloc(12),
          Buffer.alloc(15), // shorter than AES_256_GCM_TAG_SIZE (16)
          Buffer.alloc(0),
        ),
      ).toThrow(CryptoError);
    });

    it('decryptWithAad CryptoError message mentions "too short"', () => {
      expect(() =>
        AES_GCM.decryptWithAad(
          Buffer.alloc(32),
          Buffer.alloc(12),
          Buffer.alloc(15),
          Buffer.alloc(0),
        ),
      ).toThrow(/too short/);
    });

    it('decryptWithAad throws CryptoError on empty ciphertext', () => {
      expect(() =>
        AES_GCM.decryptWithAad(
          Buffer.alloc(32),
          Buffer.alloc(12),
          Buffer.alloc(0),
          Buffer.alloc(0),
        ),
      ).toThrow(CryptoError);
    });

    it('encryptWithAad throws ValidationError on non-Buffer plaintext', () => {
      expect(() =>
        AES_GCM.encryptWithAad(
          Buffer.alloc(32),
          Buffer.alloc(12),
          'not a buffer' as any,
          Buffer.alloc(0),
        ),
      ).toThrow(ValidationError);
    });

    it('encryptWithAad throws ValidationError on non-Buffer aad', () => {
      expect(() =>
        AES_GCM.encryptWithAad(
          Buffer.alloc(32),
          Buffer.alloc(12),
          Buffer.from('msg'),
          'not a buffer' as any,
        ),
      ).toThrow(ValidationError);
    });
  });

  describe('use case: Signal-style header binding', () => {
    it('binds message header to ciphertext via AAD', () => {
      const sessionKey = secureRandom(32);
      const nonce = secureRandom(12);

      const messageHeader = Buffer.concat([
        Buffer.from('ratchet_pk:'),
        secureRandom(32),
        Buffer.from(':msg_num:42'),
      ]);

      const messageBody = Buffer.from('Hey Bob, this is Alice!');

      const ciphertext = AES_GCM.encryptWithAad(
        sessionKey,
        nonce,
        messageBody,
        messageHeader,
      );

      const decrypted = AES_GCM.decryptWithAad(
        sessionKey,
        nonce,
        ciphertext,
        messageHeader,
      );
      expect(decrypted.equals(messageBody)).toBe(true);

      // Tampering header → fails
      const tamperedHeader = Buffer.from(messageHeader);
      tamperedHeader[5]! ^= 0xff;
      expect(() =>
        AES_GCM.decryptWithAad(sessionKey, nonce, ciphertext, tamperedHeader),
      ).toThrow(AuthenticationError);
    });
  });
});