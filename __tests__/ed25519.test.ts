import { describe, it, expect } from 'vitest';
import {
  Ed25519,
  SignatureError,
  ValidationError,
  ED25519_PUBLIC_KEY_SIZE,
  ED25519_PRIVATE_KEY_SIZE,
  ED25519_SIGNATURE_SIZE,
  ED25519_SEED_SIZE,
} from '../src/index';

describe('Ed25519', () => {
  describe('constants', () => {
    it('exposes correct sizes via namespace', () => {
      expect(Ed25519.PUBLIC_KEY_SIZE).toBe(32);
      expect(Ed25519.PRIVATE_KEY_SIZE).toBe(32);
      expect(Ed25519.SIGNATURE_SIZE).toBe(64);
      expect(Ed25519.SEED_SIZE).toBe(32);
    });

    it('exposes correct sizes via constants', () => {
      expect(ED25519_PUBLIC_KEY_SIZE).toBe(32);
      expect(ED25519_PRIVATE_KEY_SIZE).toBe(32);
      expect(ED25519_SIGNATURE_SIZE).toBe(64);
      expect(ED25519_SEED_SIZE).toBe(32);
    });

    it('namespace constants match top-level', () => {
      expect(Ed25519.PUBLIC_KEY_SIZE).toBe(ED25519_PUBLIC_KEY_SIZE);
      expect(Ed25519.PRIVATE_KEY_SIZE).toBe(ED25519_PRIVATE_KEY_SIZE);
      expect(Ed25519.SIGNATURE_SIZE).toBe(ED25519_SIGNATURE_SIZE);
      expect(Ed25519.SEED_SIZE).toBe(ED25519_SEED_SIZE);
    });
  });

  describe('generateKeyPair', () => {
    it('generates valid keypair', () => {
      const kp = Ed25519.generateKeyPair();
      expect(kp.publicKey).toBeInstanceOf(Buffer);
      expect(kp.privateKey).toBeInstanceOf(Buffer);
      expect(kp.publicKey.length).toBe(32);
      expect(kp.privateKey.length).toBe(32);
    });

    it('generates unique keypairs', () => {
      const a = Ed25519.generateKeyPair();
      const b = Ed25519.generateKeyPair();
      expect(a.publicKey.equals(b.publicKey)).toBe(false);
      expect(a.privateKey.equals(b.privateKey)).toBe(false);
    });
  });

  describe('keyPairFromSeed', () => {
    it('produces deterministic keypair', () => {
      const seed = Buffer.alloc(32, 0x42);
      const a = Ed25519.keyPairFromSeed(seed);
      const b = Ed25519.keyPairFromSeed(seed);
      expect(a.publicKey.equals(b.publicKey)).toBe(true);
      expect(a.privateKey.equals(b.privateKey)).toBe(true);
    });

    it('throws on wrong seed size', () => {
      expect(() => Ed25519.keyPairFromSeed(Buffer.alloc(31))).toThrow(ValidationError);
      expect(() => Ed25519.keyPairFromSeed(Buffer.alloc(33))).toThrow(ValidationError);
    });
  });

  describe('publicFromPrivate', () => {
    it('derives correct public key', () => {
      const kp = Ed25519.generateKeyPair();
      const derived = Ed25519.publicFromPrivate(kp.privateKey);
      expect(derived.equals(kp.publicKey)).toBe(true);
    });

    it('throws on wrong size', () => {
      expect(() => Ed25519.publicFromPrivate(Buffer.alloc(31))).toThrow(ValidationError);
    });
  });

  describe('sign / verify', () => {
    it('signs and verifies correctly', () => {
      const kp = Ed25519.generateKeyPair();
      const message = Buffer.from('Hello Ed25519!');
      const sig = Ed25519.sign(kp.privateKey, message);

      expect(sig.length).toBe(64);
      expect(() => Ed25519.verify(kp.publicKey, message, sig)).not.toThrow();
    });

    it('signatures are deterministic', () => {
      const kp = Ed25519.generateKeyPair();
      const message = Buffer.from('test');
      const sig1 = Ed25519.sign(kp.privateKey, message);
      const sig2 = Ed25519.sign(kp.privateKey, message);
      expect(sig1.equals(sig2)).toBe(true);
    });

    it('throws SignatureError on tampered message', () => {
      const kp = Ed25519.generateKeyPair();
      const sig = Ed25519.sign(kp.privateKey, Buffer.from('original'));
      expect(() =>
        Ed25519.verify(kp.publicKey, Buffer.from('tampered'), sig),
      ).toThrow(SignatureError);
    });

    it('throws on wrong public key', () => {
      const kpA = Ed25519.generateKeyPair();
      const kpB = Ed25519.generateKeyPair();
      const sig = Ed25519.sign(kpA.privateKey, Buffer.from('msg'));
      expect(() => Ed25519.verify(kpB.publicKey, Buffer.from('msg'), sig)).toThrow();
    });

    it('throws on tampered signature', () => {
      const kp = Ed25519.generateKeyPair();
      const sig = Ed25519.sign(kp.privateKey, Buffer.from('msg'));
      sig[0]! ^= 0xff;
      expect(() => Ed25519.verify(kp.publicKey, Buffer.from('msg'), sig)).toThrow();
    });

    it('handles empty message', () => {
      const kp = Ed25519.generateKeyPair();
      const sig = Ed25519.sign(kp.privateKey, Buffer.alloc(0));
      Ed25519.verify(kp.publicKey, Buffer.alloc(0), sig);
    });

    it('handles large message', () => {
      const kp = Ed25519.generateKeyPair();
      const msg = Buffer.alloc(100_000, 0xab);
      const sig = Ed25519.sign(kp.privateKey, msg);
      Ed25519.verify(kp.publicKey, msg, sig);
    });

    it('throws ValidationError on wrong-size inputs', () => {
      const kp = Ed25519.generateKeyPair();
      expect(() => Ed25519.sign(Buffer.alloc(31), Buffer.from('m'))).toThrow(ValidationError);
      expect(() => Ed25519.verify(Buffer.alloc(31), Buffer.from('m'), Buffer.alloc(64))).toThrow(ValidationError);
      expect(() => Ed25519.verify(kp.publicKey, Buffer.from('m'), Buffer.alloc(63))).toThrow(ValidationError);
    });
  });

  describe('verifyBool', () => {
    it('returns true for valid sig', () => {
      const kp = Ed25519.generateKeyPair();
      const message = Buffer.from('test');
      const sig = Ed25519.sign(kp.privateKey, message);
      expect(Ed25519.verifyBool(kp.publicKey, message, sig)).toBe(true);
    });

    it('returns false for invalid sig', () => {
      const kp = Ed25519.generateKeyPair();
      const sig = Buffer.alloc(64);
      expect(Ed25519.verifyBool(kp.publicKey, Buffer.from('msg'), sig)).toBe(false);
    });

    it('returns false for invalid inputs (no throw)', () => {
      const kp = Ed25519.generateKeyPair();
      expect(Ed25519.verifyBool(Buffer.alloc(31), Buffer.from('msg'), Buffer.alloc(64))).toBe(false);
      expect(Ed25519.verifyBool(kp.publicKey, Buffer.from('msg'), Buffer.alloc(63))).toBe(false);
    });
  });

  describe('RFC 8032 test vectors', () => {
    it('vector 1 (empty message)', () => {
      const seed = Buffer.from(
        '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
        'hex',
      );
      const expectedPublic = Buffer.from(
        'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
        'hex',
      );
      const expectedSig = Buffer.from(
        'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
        'hex',
      );

      const derived = Ed25519.publicFromPrivate(seed);
      expect(derived.equals(expectedPublic)).toBe(true);

      const sig = Ed25519.sign(seed, Buffer.alloc(0));
      expect(sig.equals(expectedSig)).toBe(true);

      Ed25519.verify(expectedPublic, Buffer.alloc(0), expectedSig);
    });
  });
});
