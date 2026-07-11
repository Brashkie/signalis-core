import { describe, it, expect } from 'vitest';
import {
  Curve25519,
  XEd25519,
  SignatureError,
  ValidationError,
  XED25519_PUBLIC_KEY_SIZE,
  XED25519_PRIVATE_KEY_SIZE,
  XED25519_SIGNATURE_SIZE,
  XED25519_RANDOM_SIZE,
} from '../src/index';

describe('XEd25519', () => {
  describe('constants', () => {
    it('exposes correct sizes via namespace', () => {
      expect(XEd25519.PUBLIC_KEY_SIZE).toBe(32);
      expect(XEd25519.PRIVATE_KEY_SIZE).toBe(32);
      expect(XEd25519.SIGNATURE_SIZE).toBe(64);
      expect(XEd25519.RANDOM_SIZE).toBe(64);
    });

    it('matches top-level constants', () => {
      expect(XEd25519.PUBLIC_KEY_SIZE).toBe(XED25519_PUBLIC_KEY_SIZE);
      expect(XEd25519.PRIVATE_KEY_SIZE).toBe(XED25519_PRIVATE_KEY_SIZE);
      expect(XEd25519.SIGNATURE_SIZE).toBe(XED25519_SIGNATURE_SIZE);
      expect(XEd25519.RANDOM_SIZE).toBe(XED25519_RANDOM_SIZE);
    });
  });

  describe('sign / verify roundtrip', () => {
    it('signs with Curve25519 key and verifies', () => {
      const kp = Curve25519.generateKeyPair();
      const message = Buffer.from('Hello XEd25519!');

      const sig = XEd25519.sign(kp.privateKey, message);
      expect(sig.length).toBe(64);

      expect(() => XEd25519.verify(kp.publicKey, message, sig)).not.toThrow();
    });

    it('SAME key works for both ECDH and signing', () => {
      const alice = Curve25519.generateKeyPair();
      const bob = Curve25519.generateKeyPair();

      // ECDH
      const aliceShared = Curve25519.diffieHellman(alice.privateKey, bob.publicKey);
      const bobShared = Curve25519.diffieHellman(bob.privateKey, alice.publicKey);
      expect(aliceShared.equals(bobShared)).toBe(true);

      // SAME key signs
      const sig = XEd25519.sign(alice.privateKey, Buffer.from('I am alice'));
      XEd25519.verify(alice.publicKey, Buffer.from('I am alice'), sig);
    });

    it('signatures are NOT deterministic (probabilistic)', () => {
      const kp = Curve25519.generateKeyPair();
      const message = Buffer.from('test');
      const sig1 = XEd25519.sign(kp.privateKey, message);
      const sig2 = XEd25519.sign(kp.privateKey, message);
      expect(sig1.equals(sig2)).toBe(false);

      // Both verify though
      XEd25519.verify(kp.publicKey, message, sig1);
      XEd25519.verify(kp.publicKey, message, sig2);
    });

    it('throws SignatureError on tampered message', () => {
      const kp = Curve25519.generateKeyPair();
      const sig = XEd25519.sign(kp.privateKey, Buffer.from('original'));
      expect(() =>
        XEd25519.verify(kp.publicKey, Buffer.from('tampered'), sig),
      ).toThrow(SignatureError);
    });

    it('throws on wrong key', () => {
      const kpA = Curve25519.generateKeyPair();
      const kpB = Curve25519.generateKeyPair();
      const sig = XEd25519.sign(kpA.privateKey, Buffer.from('msg'));
      expect(() => XEd25519.verify(kpB.publicKey, Buffer.from('msg'), sig)).toThrow();
    });

    it('throws on tampered signature', () => {
      const kp = Curve25519.generateKeyPair();
      const sig = XEd25519.sign(kp.privateKey, Buffer.from('msg'));
      sig[0]! ^= 0xff;
      expect(() => XEd25519.verify(kp.publicKey, Buffer.from('msg'), sig)).toThrow();
    });

    it('handles empty message', () => {
      const kp = Curve25519.generateKeyPair();
      const sig = XEd25519.sign(kp.privateKey, Buffer.alloc(0));
      XEd25519.verify(kp.publicKey, Buffer.alloc(0), sig);
    });

    it('handles large message', () => {
      const kp = Curve25519.generateKeyPair();
      const msg = Buffer.alloc(100_000, 0xab);
      const sig = XEd25519.sign(kp.privateKey, msg);
      XEd25519.verify(kp.publicKey, msg, sig);
    });
  });

  describe('signWithRandom', () => {
    it('deterministic with same random', () => {
      const kp = Curve25519.generateKeyPair();
      const random = Buffer.alloc(64, 0x42);
      const sig1 = XEd25519.signWithRandom(kp.privateKey, Buffer.from('msg'), random);
      const sig2 = XEd25519.signWithRandom(kp.privateKey, Buffer.from('msg'), random);
      expect(sig1.equals(sig2)).toBe(true);
    });

    it('throws ValidationError on wrong random size', () => {
      const kp = Curve25519.generateKeyPair();
      expect(() =>
        XEd25519.signWithRandom(kp.privateKey, Buffer.from('msg'), Buffer.alloc(63)),
      ).toThrow(ValidationError);
      expect(() =>
        XEd25519.signWithRandom(kp.privateKey, Buffer.from('msg'), Buffer.alloc(65)),
      ).toThrow(ValidationError);
    });
  });

  describe('verifyBool', () => {
    it('returns true for valid sig', () => {
      const kp = Curve25519.generateKeyPair();
      const sig = XEd25519.sign(kp.privateKey, Buffer.from('msg'));
      expect(XEd25519.verifyBool(kp.publicKey, Buffer.from('msg'), sig)).toBe(true);
    });

    it('returns false for invalid sig', () => {
      const kp = Curve25519.generateKeyPair();
      expect(
        XEd25519.verifyBool(kp.publicKey, Buffer.from('msg'), Buffer.alloc(64)),
      ).toBe(false);
    });

    it('returns false for invalid inputs (no throw)', () => {
      expect(
        XEd25519.verifyBool(Buffer.alloc(31), Buffer.from('msg'), Buffer.alloc(64)),
      ).toBe(false);
    });
  });

  describe('input validation', () => {
    it('throws ValidationError on wrong private key size', () => {
      expect(() => XEd25519.sign(Buffer.alloc(31), Buffer.from('msg'))).toThrow(ValidationError);
    });

    it('throws ValidationError on wrong public key size', () => {
      expect(() =>
        XEd25519.verify(Buffer.alloc(31), Buffer.from('msg'), Buffer.alloc(64)),
      ).toThrow(ValidationError);
    });

    it('throws ValidationError on wrong signature size', () => {
      const kp = Curve25519.generateKeyPair();
      expect(() =>
        XEd25519.verify(kp.publicKey, Buffer.from('msg'), Buffer.alloc(63)),
      ).toThrow(ValidationError);
    });
  });
});
