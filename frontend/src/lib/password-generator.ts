const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.?';

const REQUIRED_CHARACTER_SETS = [LOWERCASE, UPPERCASE, DIGITS, SYMBOLS] as const;

export const PASSWORD_ALPHABET = REQUIRED_CHARACTER_SETS.join('');
export const DEFAULT_PASSWORD_LENGTH = 24;
export const MIN_PASSWORD_LENGTH = 16;
export const MAX_PASSWORD_LENGTH = 128;

const UINT32_RANGE = 0x1_0000_0000;
const MAX_REJECTION_ATTEMPTS = 128;

export type RandomUint32Source = () => number;
export type RandomIndexSource = (maxExclusive: number) => number;

function cryptoUint32(): number {
  const values = new Uint32Array(1);
  globalThis.crypto.getRandomValues(values);
  return values[0];
}

/**
 * Return an integer in [0, maxExclusive) without modulo bias.
 *
 * Values in the incomplete tail of the uint32 range are rejected before the
 * modulo operation. Keeping the uint32 source injectable makes that rejection
 * path testable without weakening the production Web Crypto source.
 */
export function unbiasedRandomIndex(
  maxExclusive: number,
  nextUint32: RandomUint32Source = cryptoUint32
): number {
  if (!Number.isSafeInteger(maxExclusive) || maxExclusive < 1 || maxExclusive > UINT32_RANGE) {
    throw new RangeError('maxExclusive must be an integer between 1 and 2^32');
  }

  const acceptanceLimit = Math.floor(UINT32_RANGE / maxExclusive) * maxExclusive;
  for (let attempt = 0; attempt < MAX_REJECTION_ATTEMPTS; attempt += 1) {
    const value = nextUint32();
    if (!Number.isInteger(value) || value < 0 || value >= UINT32_RANGE) {
      throw new RangeError('The random source must return an unsigned 32-bit integer');
    }
    if (value < acceptanceLimit) return value % maxExclusive;
  }

  // The chance of Web Crypto reaching this branch with these small character
  // pools is negligible. The bound keeps a broken or injected random source
  // from freezing the vault form forever.
  throw new Error('Secure random source repeatedly returned unusable values');
}

function assertPasswordLength(length: number): void {
  if (!Number.isSafeInteger(length) || length < MIN_PASSWORD_LENGTH || length > MAX_PASSWORD_LENGTH) {
    throw new RangeError(
      `Password length must be an integer between ${MIN_PASSWORD_LENGTH} and ${MAX_PASSWORD_LENGTH}`
    );
  }
}

function characterFrom(characterSet: string, randomIndex: RandomIndexSource): string {
  const index = randomIndex(characterSet.length);
  if (!Number.isSafeInteger(index) || index < 0 || index >= characterSet.length) {
    throw new RangeError('The random index source returned an out-of-range value');
  }
  return characterSet[index];
}

export function passwordMeetsCharacterRequirements(password: string): boolean {
  return REQUIRED_CHARACTER_SETS.every((characterSet) =>
    Array.from(password).some((character) => characterSet.includes(character))
  );
}

/**
 * Conservative estimate that ignores all entropy added by the secure shuffle.
 * The four required characters are sampled from their own sets and every other
 * character is sampled from the full alphabet.
 */
export function estimatedPasswordEntropyBits(length = DEFAULT_PASSWORD_LENGTH): number {
  assertPasswordLength(length);
  const unconstrainedCharacters = length - REQUIRED_CHARACTER_SETS.length;
  return (
    unconstrainedCharacters * Math.log2(PASSWORD_ALPHABET.length) +
    REQUIRED_CHARACTER_SETS.reduce((bits, characterSet) => bits + Math.log2(characterSet.length), 0)
  );
}

/** Generate a local-only password using Web Crypto and unbiased sampling. */
export function generateStrongPassword(
  length = DEFAULT_PASSWORD_LENGTH,
  randomIndex: RandomIndexSource = unbiasedRandomIndex
): string {
  assertPasswordLength(length);

  const characters = REQUIRED_CHARACTER_SETS.map((characterSet) =>
    characterFrom(characterSet, randomIndex)
  );

  while (characters.length < length) {
    characters.push(characterFrom(PASSWORD_ALPHABET, randomIndex));
  }

  // Fisher-Yates, using the same rejection-sampled secure index source. This
  // avoids predictable class positions while preserving the coverage guarantee.
  for (let index = characters.length - 1; index > 0; index -= 1) {
    const swapIndex = randomIndex(index + 1);
    if (!Number.isSafeInteger(swapIndex) || swapIndex < 0 || swapIndex > index) {
      throw new RangeError('The random index source returned an out-of-range value');
    }
    [characters[index], characters[swapIndex]] = [characters[swapIndex], characters[index]];
  }

  return characters.join('');
}
