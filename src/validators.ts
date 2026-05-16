/**
 * Input validators for signalis-core.
 *
 * All validators throw `ValidationError` with detailed information.
 *
 * @packageDocumentation
 */

import { ValidationError, LengthError } from './errors';
import {
  HKDF_MAX_OUTPUT_SIZE,
} from './constants';

/**
 * Assert that a value is a `Buffer`.
 *
 * @throws {ValidationError} If `value` is not a Buffer.
 */
export function assertBuffer(value: unknown, parameter: string): asserts value is Buffer {
  if (!Buffer.isBuffer(value)) {
    throw new ValidationError(`${parameter} must be a Buffer`, {
      parameter,
      expected: 'Buffer',
      actual: typeof value,
    });
  }
}

/**
 * Assert that a Buffer has exactly the expected length.
 *
 * @throws {ValidationError} If length mismatch.
 */
export function assertBufferLength(
  value: Buffer,
  expectedLength: number,
  parameter: string,
): void {
  if (value.length !== expectedLength) {
    throw new ValidationError(
      `${parameter} must be ${expectedLength} bytes, got ${value.length}`,
      {
        parameter,
        expected: `${expectedLength} bytes`,
        actual: value.length,
      },
    );
  }
}

/**
 * Combined check: must be a Buffer of exactly N bytes.
 */
export function assertBufferOfSize(
  value: unknown,
  expectedLength: number,
  parameter: string,
): asserts value is Buffer {
  assertBuffer(value, parameter);
  assertBufferLength(value, expectedLength, parameter);
}

/**
 * Assert that a number is a positive integer.
 */
export function assertPositiveInteger(value: unknown, parameter: string): asserts value is number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new ValidationError(`${parameter} must be a non-negative integer`, {
      parameter,
      expected: 'non-negative integer',
      actual: String(value),
    });
  }
}

/**
 * Assert HKDF output length is within bounds.
 */
export function assertHkdfLength(length: unknown): asserts length is number {
  assertPositiveInteger(length, 'length');
  if ((length as number) > HKDF_MAX_OUTPUT_SIZE) {
    throw new LengthError(
      `HKDF output length cannot exceed ${HKDF_MAX_OUTPUT_SIZE} bytes (255 * 32)`,
      {
        expected: `<= ${HKDF_MAX_OUTPUT_SIZE}`,
        actual: length as number,
      },
    );
  }
  if ((length as number) === 0) {
    throw new LengthError('HKDF output length must be greater than 0', {
      expected: '> 0',
      actual: 0,
    });
  }
}

/**
 * Check if two Buffers have the same length (utility for tests).
 */
export function buffersSameLength(a: Buffer, b: Buffer): boolean {
  return a.length === b.length;
}
