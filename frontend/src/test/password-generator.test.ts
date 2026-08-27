import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DEFAULT_PASSWORD_LENGTH,
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
  estimatedPasswordEntropyBits,
  generateStrongPassword,
  passwordMeetsCharacterRequirements,
  unbiasedRandomIndex,
} from '@/lib/password-generator';

describe('password generator', () => {
  afterEach(() => vi.restoreAllMocks());

  it('generates the requested length with every required character class', () => {
    const password = generateStrongPassword();

    expect(password).toHaveLength(DEFAULT_PASSWORD_LENGTH);
    expect(passwordMeetsCharacterRequirements(password)).toBe(true);
    expect(password).toMatch(/[a-z]/);
    expect(password).toMatch(/[A-Z]/);
    expect(password).toMatch(/[0-9]/);
    expect(password).toMatch(/[^A-Za-z0-9]/);
  });

  it('provides more than 128 bits of conservative estimated entropy by default', () => {
    expect(estimatedPasswordEntropyBits()).toBeGreaterThanOrEqual(128);
  });

  it('validates length deterministically before requesting randomness', () => {
    const randomIndex = vi.fn(() => 0);

    expect(() => generateStrongPassword(MIN_PASSWORD_LENGTH - 1, randomIndex)).toThrow(RangeError);
    expect(() => generateStrongPassword(MAX_PASSWORD_LENGTH + 1, randomIndex)).toThrow(RangeError);
    expect(() => generateStrongPassword(20.5, randomIndex)).toThrow(RangeError);
    expect(randomIndex).not.toHaveBeenCalled();
  });

  it('rejects the incomplete uint32 tail instead of introducing modulo bias', () => {
    const values = [0xffff_ffff, 7];
    const nextUint32 = vi.fn(() => values.shift() ?? 0);

    expect(unbiasedRandomIndex(10, nextUint32)).toBe(7);
    expect(nextUint32).toHaveBeenCalledTimes(2);
  });

  it('fails closed instead of looping forever on a broken random source', () => {
    const nextUint32 = vi.fn(() => 0xffff_ffff);

    expect(() => unbiasedRandomIndex(10, nextUint32)).toThrow(
      'Secure random source repeatedly returned unusable values'
    );
    expect(nextUint32).toHaveBeenCalledTimes(128);
  });

  it('uses Web Crypto and never calls Math.random', () => {
    const mathRandom = vi.spyOn(Math, 'random').mockImplementation(() => {
      throw new Error('Math.random must not be used');
    });
    const getRandomValues = vi
      .spyOn(globalThis.crypto, 'getRandomValues')
      .mockImplementation(<T extends ArrayBufferView | null>(array: T): T => {
        if (array instanceof Uint32Array) array[0] = 17;
        return array;
      });

    const password = generateStrongPassword();

    expect(passwordMeetsCharacterRequirements(password)).toBe(true);
    expect(getRandomValues).toHaveBeenCalled();
    expect(mathRandom).not.toHaveBeenCalled();
  });
});
