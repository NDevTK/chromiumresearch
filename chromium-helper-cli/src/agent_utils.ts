import crypto from 'node:crypto';

/**
 * Computes the SHA256 hash of a given string.
 * @param content The string content to hash.
 * @returns The SHA256 hash as a hex string.
 */
export function computeSha256Hash(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Escapes special characters in a string for use in a regular expression.
 * @param str The string to escape.
 * @returns The escaped string.
 */
export function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); // $& means the whole matched string
}
