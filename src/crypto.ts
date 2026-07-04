// src/crypto.ts

// ============================================================
// CONSTANTS
// ============================================================

// Base32 alphabet: Excludes 0/O and 1/I/L to prevent visual ambiguity.
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const ALPHABET_LEN = ALPHABET.length; // 31

// Format: MX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
// Segments: 7 × 5 = 35 characters (last character is checksum)
// Total length: 3 ("MX-") + 35 (chars) + 6 (dashes) = 44 characters
const LICENSE_TOTAL_LENGTH = 44;
const LICENSE_SEGMENT_COUNT = 7;
const LICENSE_SEGMENT_LENGTH = 5;
const LICENSE_DATA_CHARS = LICENSE_SEGMENT_COUNT * LICENSE_SEGMENT_LENGTH - 1; // 34 random chars

// Pre-compiled regex for format validation (before checksum)
const LICENSE_REGEX = /^MX-[A-Z2-9]{5}-[A-Z2-9]{5}-[A-Z2-9]{5}-[A-Z2-9]{5}-[A-Z2-9]{5}-[A-Z2-9]{5}-[A-Z2-9]{5}$/;

// SHA-256 hex: exactly 64 lowercase hexadecimal characters
const DEVICE_HASH_REGEX = /^[a-f0-9]{64}$/;

// PKCS#8 prefix for Ed25519 private keys (16 bytes, DER-encoded header)
// OID 1.3.101.112 = Ed25519
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
]);

// ============================================================
// TIMING-SAFE COMPARISON
// ============================================================

/**
 * Constant-time string comparison.
 * Prevents timing side-channel attacks that could leak
 * information about valid license keys or device hashes.
 */
export function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) {
    // Still iterate to maintain constant time relative to 'a' length
    let dummy = 0;
    for (let i = 0; i < a.length; i++) {
      dummy |= a.charCodeAt(i) ^ a.charCodeAt(i);
    }
    return false;
  }
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

// ============================================================
// ENCODING HELPERS
// ============================================================

export function hexToArrayBuffer(hex: string): ArrayBuffer {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex string: odd length');
  const buffer = new ArrayBuffer(hex.length / 2);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < hex.length; i += 2) {
    const byte = parseInt(hex.substring(i, i + 2), 16);
    if (Number.isNaN(byte)) throw new Error('Invalid hex character');
    view[i / 2] = byte;
  }
  return buffer;
}

export function arrayBufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

export function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

export function base64UrlToUint8Array(base64url: string): Uint8Array {
  const padded = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = padded.length % 4;
  const base64 = pad ? padded + '='.repeat(4 - pad) : padded;
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ============================================================
// FORMAT VALIDATORS
// ============================================================

/**
 * Validates license key format AND checksum.
 * This is the single source of truth for license validity checking.
 */
export function isValidLicense(license: string): boolean {
  if (license.length !== LICENSE_TOTAL_LENGTH) return false;
  if (!LICENSE_REGEX.test(license)) return false;
  
  // Extract only the data characters (strip "MX-" prefix and dashes)
  const stripped = license.replace(/^MX-/, '').replace(/-/g, '');
  if (stripped.length !== LICENSE_SEGMENT_COUNT * LICENSE_SEGMENT_LENGTH) return false;
  
  // Verify checksum (last character)
  const dataChars = stripped.substring(0, LICENSE_DATA_CHARS);
  const expectedChecksum = computeChecksum(dataChars);
  const actualChecksum = stripped[LICENSE_DATA_CHARS];
  
  return constantTimeEquals(expectedChecksum, actualChecksum);
}

/**
 * Validates that a device hash is exactly 64 lowercase hex characters (SHA-256).
 */
export function isValidDeviceHash(hash: string): boolean {
  return DEVICE_HASH_REGEX.test(hash);
}

/**
 * Validates strict SemVer format: X.Y.Z
 */
export function isValidAppVersion(version: string): boolean {
  return /^\d+\.\d+\.\d+$/.test(version);
}

// ============================================================
// LICENSE CHECKSUM
// ============================================================

/**
 * Computes a weighted checksum character over the data characters.
 * Uses positional weighting to detect both single-character errors
 * and adjacent character transpositions.
 * 
 * Algorithm: sum(alphabetIndex(char_i) * (i + 1)) mod ALPHABET_LEN
 */
function computeChecksum(dataChars: string): string {
  let weightedSum = 0;
  for (let i = 0; i < dataChars.length; i++) {
    const charIndex = ALPHABET.indexOf(dataChars[i]);
    if (charIndex === -1) throw new Error('Invalid character in license data');
    weightedSum += charIndex * (i + 1);
  }
  return ALPHABET[weightedSum % ALPHABET_LEN];
}

// ============================================================
// LICENSE GENERATION
// ============================================================

/**
 * Generates a cryptographically secure license key with embedded checksum.
 * Format: MX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXC
 * Where C is a checksum character that validates the preceding 34 characters.
 * 
 * Uses crypto.getRandomValues() with rejection-free modular arithmetic.
 * ALPHABET_LEN (31) does not evenly divide 256, so we use rejection sampling
 * to eliminate modulo bias entirely.
 */
export function generateLicenseKey(): string {
  const maxValid = Math.floor(256 / ALPHABET_LEN) * ALPHABET_LEN; // 248
  const randomChars: string[] = [];
  
  // Generate 34 random characters using rejection sampling
  while (randomChars.length < LICENSE_DATA_CHARS) {
    const bytes = new Uint8Array(LICENSE_DATA_CHARS - randomChars.length);
    crypto.getRandomValues(bytes);
    
    for (let i = 0; i < bytes.length && randomChars.length < LICENSE_DATA_CHARS; i++) {
      if (bytes[i] < maxValid) {
        randomChars.push(ALPHABET[bytes[i] % ALPHABET_LEN]);
      }
    }
  }
  
  // Compute checksum
  const checksumChar = computeChecksum(randomChars.join(''));
  const allChars = [...randomChars, checksumChar];
  
  // Format into segments: MX-XXXXX-XXXXX-...
  let key = 'MX-';
  for (let i = 0; i < LICENSE_SEGMENT_COUNT; i++) {
    const start = i * LICENSE_SEGMENT_LENGTH;
    key += allChars.slice(start, start + LICENSE_SEGMENT_LENGTH).join('');
    if (i < LICENSE_SEGMENT_COUNT - 1) key += '-';
  }
  
  return key;
}

// ============================================================
// Ed25519 KEY MANAGEMENT
// ============================================================

/**
 * Wraps a raw 32-byte Ed25519 seed into PKCS#8 DER format
 * for import into the Web Crypto API.
 */
function wrapEd25519PrivateKeyPKCS8(rawSeed: Uint8Array): Uint8Array {
  if (rawSeed.length !== 32) throw new Error('Ed25519 seed must be exactly 32 bytes');
  const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + rawSeed.length);
  pkcs8.set(ED25519_PKCS8_PREFIX);
  pkcs8.set(rawSeed, ED25519_PKCS8_PREFIX.length);
  return pkcs8;
}

/**
 * Imports a hex-encoded Ed25519 private key (32-byte seed) as a CryptoKey.
 */
async function importPrivateKey(privateKeyHex: string): Promise<CryptoKey> {
  const rawSeed = new Uint8Array(hexToArrayBuffer(privateKeyHex));
  const pkcs8 = wrapEd25519PrivateKeyPKCS8(rawSeed);
  
  return crypto.subtle.importKey(
    'pkcs8',
    pkcs8.buffer,
    'Ed25519',
    false,
    ['sign']
  );
}

/**
 * Imports a hex-encoded Ed25519 public key (32 bytes) as a CryptoKey.
 */
async function importPublicKey(publicKeyHex: string): Promise<CryptoKey> {
  const rawKey = hexToArrayBuffer(publicKeyHex);
  
  return crypto.subtle.importKey(
    'raw',
    rawKey,
    'Ed25519',
    false,
    ['verify']
  );
}

// ============================================================
// TOKEN SIGNING
// ============================================================

export interface TokenPayload {
  license: string;
  device: string;
  plan: string;
  iat: number;
  exp: number | null;
  jti: string;
  ver: number;
}

export interface SignedToken {
  p: string; // Base64Url-encoded payload
  s: string; // Base64Url-encoded signature
}

/**
 * Signs a token payload using the Ed25519 private key.
 * Returns a compact JSON object with payload and signature.
 */
export async function signToken(
  payload: TokenPayload,
  privateKeyHex: string
): Promise<string> {
  const cryptoKey = await importPrivateKey(privateKeyHex);
  
  // Deterministic JSON serialization (sorted keys for consistency)
  const payloadJson = JSON.stringify(payload, Object.keys(payload).sort());
  const payloadBytes = new TextEncoder().encode(payloadJson);
  
  const signatureBuffer = await crypto.subtle.sign('Ed25519', cryptoKey, payloadBytes);
  
  const token: SignedToken = {
    p: arrayBufferToBase64Url(payloadBytes.buffer),
    s: arrayBufferToBase64Url(signatureBuffer)
  };
  
  return JSON.stringify(token);
}

// ============================================================
// TOKEN VERIFICATION (with Key Rotation Support)
// ============================================================

/**
 * Verifies a signed token against one or more Ed25519 public keys.
 * Supports seamless key rotation: tries each key until one succeeds.
 * 
 * Returns the parsed TokenPayload if valid, or null if:
 * - Token format is invalid
 * - Signature is invalid for ALL provided keys
 * - JSON parsing fails
 */
export async function verifyTokenSignature(
  tokenString: string,
  publicKeysHex: string[]
): Promise<TokenPayload | null> {
  if (publicKeysHex.length === 0) return null;
  
  let tokenObj: SignedToken;
  try {
    tokenObj = JSON.parse(tokenString);
    if (!tokenObj.p || !tokenObj.s) return null;
    if (typeof tokenObj.p !== 'string' || typeof tokenObj.s !== 'string') return null;
  } catch {
    return null;
  }
  
  // Decode payload bytes
  let payloadBytes: Uint8Array;
  let payloadJson: string;
  try {
    payloadBytes = base64UrlToUint8Array(tokenObj.p);
    payloadJson = new TextDecoder().decode(payloadBytes);
  } catch {
    return null;
  }
  
  // Decode signature bytes
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64UrlToUint8Array(tokenObj.s);
  } catch {
    return null;
  }
  
  // Try each public key (supports rotation)
  for (const publicKeyHex of publicKeysHex) {
    try {
      const cryptoKey = await importPublicKey(publicKeyHex);
      const isValid = await crypto.subtle.verify(
        'Ed25519',
        cryptoKey,
        signatureBytes,
        payloadBytes
      );
      
      if (isValid) {
        // Parse and validate payload structure
        const payload = JSON.parse(payloadJson);
        if (!isTokenPayloadValid(payload)) return null;
        return payload as TokenPayload;
      }
    } catch {
      // Key import failed or verification error; try next key
      continue;
    }
  }
  
  return null; // No key matched
}

/**
 * Structural validation of a decoded token payload.
 * Ensures all required fields exist with correct types.
 */
function isTokenPayloadValid(payload: any): payload is TokenPayload {
  return (
    payload !== null &&
    typeof payload === 'object' &&
    typeof payload.license === 'string' &&
    typeof payload.device === 'string' &&
    typeof payload.plan === 'string' &&
    typeof payload.iat === 'number' &&
    (payload.exp === null || typeof payload.exp === 'number') &&
    typeof payload.jti === 'string' &&
    typeof payload.ver === 'number'
  );
}