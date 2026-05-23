/**
 * Typed error classes for signalis-core.
 *
 * All errors extend the base `SignalisError` class for easy `instanceof` checks.
 *
 * @packageDocumentation
 */

/**
 * Base error class for all signalis-core errors.
 *
 * @example
 * ```ts
 * try {
 *   Curve25519.diffieHellman(invalidKey, peer);
 * } catch (e) {
 *   if (e instanceof SignalisError) {
 *     console.error('Crypto error:', e.code, e.message);
 *   }
 * }
 * ```
 */
export class SignalisError extends Error {
  /** Error code for programmatic handling. */
  public readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = 'SignalisError';
    this.code = code;
    // Maintain proper stack trace
    if (typeof Error.captureStackTrace === 'function') {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

/**
 * Thrown when input validation fails (wrong size, wrong type, etc.).
 */
export class ValidationError extends SignalisError {
  /** Name of the parameter that failed validation. */
  public readonly parameter?: string;

  /** Expected value description. */
  public readonly expected?: string;

  /** Actual value received. */
  public readonly actual?: string | number;

  constructor(
    message: string,
    options: {
      parameter?: string;
      expected?: string;
      actual?: string | number;
    } = {},
  ) {
    super(message, 'VALIDATION_ERROR');
    this.name = 'ValidationError';
    this.parameter = options.parameter;
    this.expected = options.expected;
    this.actual = options.actual;
  }
}

/**
 * Thrown when a crypto operation fails (decryption, MAC verification, etc.).
 */
export class CryptoError extends SignalisError {
  /** The crypto operation that failed. */
  public readonly operation: string;

  constructor(message: string, operation: string) {
    super(message, 'CRYPTO_ERROR');
    this.name = 'CryptoError';
    this.operation = operation;
  }
}

/**
 * Thrown when AEAD authentication fails (e.g., AES-GCM tag mismatch).
 *
 * This is a security-critical error: the ciphertext was tampered with
 * or the wrong key was used.
 */
export class AuthenticationError extends CryptoError {
  constructor(message = 'Authentication tag verification failed') {
    super(message, 'authenticate');
    this.name = 'AuthenticationError';
  }
}

/**
 * Thrown when a key derivation or key agreement operation fails.
 */
export class KeyDerivationError extends CryptoError {
  constructor(message: string) {
    super(message, 'derive_key');
    this.name = 'KeyDerivationError';
  }
}

/**
 * Thrown when a digital signature verification fails (NEW in v0.2.0).
 *
 * Used by Ed25519 and XEd25519 verification.
 */
export class SignatureError extends CryptoError {
  constructor(message = 'Signature verification failed') {
    super(message, 'verify_signature');
    this.name = 'SignatureError';
  }
}

/**
 * Thrown when the requested output length is invalid (e.g., HKDF > 8160 bytes).
 */
export class LengthError extends ValidationError {
  constructor(message: string, options: { expected?: string; actual?: number } = {}) {
    super(message, options);
    this.name = 'LengthError';
  }
}
