// src/license.ts

import { Env, LicenseStatus, LogAction } from './types';
import * as db from './database';
import {
  generateLicenseKey,
  signToken,
  verifyTokenSignature,
  constantTimeEquals,
  TokenPayload,
} from './crypto';

// ============================================================
// ERROR TYPES
// ============================================================

/**
 * Granular error codes for structured logging and precise client feedback.
 * Every failure path has a unique, descriptive code.
 */
export enum ErrorCode {
  // Activation Errors
  MAINTENANCE_MODE = 'MAINTENANCE_MODE',
  APP_OUTDATED = 'APP_OUTDATED',
  LICENSE_NOT_FOUND = 'LICENSE_NOT_FOUND',
  LICENSE_REVOKED = 'LICENSE_REVOKED',
  LICENSE_EXPIRED = 'LICENSE_EXPIRED',
  LICENSE_ALREADY_USED = 'LICENSE_ALREADY_USED',
  LICENSE_ALREADY_USED_THIS_DEVICE = 'LICENSE_ALREADY_USED_THIS_DEVICE',
  ACTIVATION_RACE = 'ACTIVATION_RACE',
  
  // Verification Errors
  TOKEN_MALFORMED = 'TOKEN_MALFORMED',
  TOKEN_SIGNATURE_INVALID = 'TOKEN_SIGNATURE_INVALID',
  TOKEN_VERSION_MISMATCH = 'TOKEN_VERSION_MISMATCH',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  DEVICE_MISMATCH = 'DEVICE_MISMATCH',
  DEVICE_NOT_FOUND = 'DEVICE_NOT_FOUND',
  
  // Admin Errors
  LICENSE_RESET_INVALID_STATE = 'LICENSE_RESET_INVALID_STATE',
}

export class LicenseError extends Error {
  constructor(
    public code: ErrorCode,
    message: string,
    public httpStatus: number = 400
  ) {
    super(message);
    this.name = 'LicenseError';
  }
}

// ============================================================
// HELPERS
// ============================================================

/**
 * Compares two SemVer strings.
 * Returns: 1 if a > b, -1 if a < b, 0 if equal.
 */
function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if (pa[i] > pb[i]) return 1;
    if (pa[i] < pb[i]) return -1;
  }
  return 0;
}

/**
 * Returns the current Unix timestamp in seconds.
 */
function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Builds the ordered array of public keys for verification.
 * Supports seamless key rotation: current key first, then previous.
 */
function getPublicKeyChain(env: Env): string[] {
  const keys: string[] = [];
  if (env.ED25519_PUBLIC_KEY) keys.push(env.ED25519_PUBLIC_KEY);
  if (env.ED25519_PUBLIC_KEY_PREVIOUS) keys.push(env.ED25519_PUBLIC_KEY_PREVIOUS);
  return keys;
}

// ============================================================
// PUBLIC OPERATION: ACTIVATE
// ============================================================

export interface ActivationResult {
  token: string;
  ver: number;
}

/**
 * Activates a license for a device.
 * 
 * Flow:
 * 1. Check maintenance mode and app version compatibility.
 * 2. Validate license state (exists, not revoked, not expired).
 * 3. Find or create device record.
 * 4. Atomic activation via D1 batch transaction.
 * 5. Sign activation token.
 * 6. Record audit log.
 */
export async function activate(
  env: Env,
  licenseKey: string,
  deviceHash: string,
  appVersion: string
): Promise<ActivationResult> {

  // ----------------------------------------------------------
  // Step 1: Global Gates
  // ----------------------------------------------------------
  const settings = await db.getSettings(env.DB);
  
  if (settings.maintenance_mode === 1) {
    throw new LicenseError(
      ErrorCode.MAINTENANCE_MODE,
      'Backend is currently in maintenance mode.',
      503
    );
  }
  
  if (!settings.allow_activation) {
    throw new LicenseError(
      ErrorCode.MAINTENANCE_MODE,
      'Activations are temporarily disabled.',
      503
    );
  }

  if (compareVersions(appVersion, settings.minimum_app_version) < 0) {
    throw new LicenseError(
      ErrorCode.APP_OUTDATED,
      'Please update your app to the latest version.',
      426
    );
  }

  // ----------------------------------------------------------
  // Step 2: License State Pre-Check
  // ----------------------------------------------------------
  const license = await db.getLicenseByKey(env.DB, licenseKey);
  
  if (!license) {
    await db.insertLog(env.DB, licenseKey, deviceHash, LogAction.FAILED, ErrorCode.LICENSE_NOT_FOUND, env.APP_VERSION);
    throw new LicenseError(ErrorCode.LICENSE_NOT_FOUND, 'License does not exist.', 404);
  }

  if (license.status === LicenseStatus.REVOKED) {
    await db.insertLog(env.DB, licenseKey, deviceHash, LogAction.FAILED, ErrorCode.LICENSE_REVOKED, env.APP_VERSION);
    throw new LicenseError(ErrorCode.LICENSE_REVOKED, 'License has been revoked.', 403);
  }

  if (license.status === LicenseStatus.EXPIRED) {
    await db.insertLog(env.DB, licenseKey, deviceHash, LogAction.FAILED, ErrorCode.LICENSE_EXPIRED, env.APP_VERSION);
    throw new LicenseError(ErrorCode.LICENSE_EXPIRED, 'License has expired.', 403);
  }

  if (license.expires_at !== null && license.expires_at < nowSeconds()) {
    await db.insertLog(env.DB, licenseKey, deviceHash, LogAction.FAILED, ErrorCode.LICENSE_EXPIRED, env.APP_VERSION);
    throw new LicenseError(ErrorCode.LICENSE_EXPIRED, 'License has expired.', 403);
  }

  // ----------------------------------------------------------
  // Step 3: Find or Create Device
  // ----------------------------------------------------------
  let device = await db.getDeviceByHash(env.DB, deviceHash);
  
  if (device && license.status === LicenseStatus.ACTIVE && license.device_id === device.id) {
    // Same device re-activating an already active license
    // This can happen after a reinstall where storage survived
    await db.insertLog(env.DB, licenseKey, deviceHash, LogAction.VERIFY, ErrorCode.LICENSE_ALREADY_USED_THIS_DEVICE, env.APP_VERSION);
    throw new LicenseError(
      ErrorCode.LICENSE_ALREADY_USED_THIS_DEVICE,
      'License is already active on this device. Use /verify instead.',
      409
    );
  }

  if (license.status === LicenseStatus.ACTIVE && (!device || license.device_id !== device.id)) {
    // Different device trying to use an already-activated license
    await db.insertLog(env.DB, licenseKey, deviceHash, LogAction.FAILED, ErrorCode.LICENSE_ALREADY_USED, env.APP_VERSION);
    throw new LicenseError(
      ErrorCode.LICENSE_ALREADY_USED,
      'License is already activated on another device.',
      409
    );
  }

  if (!device) {
    device = await db.insertDevice(env.DB, deviceHash);
  }

  // ----------------------------------------------------------
  // Step 4: Atomic Activation (D1 Batch Transaction)
  // ----------------------------------------------------------
  const now = nowSeconds();
  
  const activationResult = await db.atomicActivate(
    env.DB,
    licenseKey,
    device.id,
    now
  );

  if (!activationResult) {
    // Race condition: another request activated this license between our check and update
    await db.insertLog(env.DB, licenseKey, deviceHash, LogAction.FAILED, ErrorCode.ACTIVATION_RACE, env.APP_VERSION);
    throw new LicenseError(
      ErrorCode.ACTIVATION_RACE,
      'License was just activated by another request.',
      409
    );
  }

  // ----------------------------------------------------------
  // Step 5: Sign Activation Token
  // ----------------------------------------------------------
  const payload: TokenPayload = {
    license: licenseKey,
    device: deviceHash,
    plan: license.plan,
    iat: now,
    exp: license.expires_at,
    jti: crypto.randomUUID(),
    ver: settings.token_version,
  };

  const token = await signToken(payload, env.ED25519_PRIVATE_KEY);

  // ----------------------------------------------------------
  // Step 6: Audit Log
  // ----------------------------------------------------------
  await db.insertLog(env.DB, licenseKey, deviceHash, LogAction.ACTIVATED, 'SUCCESS', env.APP_VERSION);

  return {
    token,
    ver: settings.token_version,
  };
}

// ============================================================
// PUBLIC OPERATION: VERIFY
// ============================================================

export interface VerifyResult {
  status: LicenseStatus;
}

/**
 * Verifies a signed activation token.
 * 
 * Flow:
 * 1. Cryptographic signature verification (delegated to crypto.ts).
 * 2. Token version check.
 * 3. Expiration check.
 * 4. Device hash binding check (timing-safe).
 * 5. Database state check (ensure not revoked since token issuance).
 * 6. Update verification metrics.
 */
export async function verify(
  env: Env,
  tokenString: string,
  deviceHash: string
): Promise<VerifyResult> {

  const settings = await db.getSettings(env.DB);
  
  if (!settings.allow_verify) {
    throw new LicenseError(
      ErrorCode.MAINTENANCE_MODE,
      'Verification is temporarily disabled.',
      503
    );
  }

  const now = nowSeconds();
  const publicKeys = getPublicKeyChain(env);

  // ----------------------------------------------------------
  // Step 1: Cryptographic Verification (delegated to crypto.ts)
  // ----------------------------------------------------------
  const payload = await verifyTokenSignature(tokenString, publicKeys);
  
  if (!payload) {
    throw new LicenseError(
      ErrorCode.TOKEN_SIGNATURE_INVALID,
      'Token signature is invalid, expired key, or tampered.',
      401
    );
  }

  // ----------------------------------------------------------
  // Step 2: Token Version Check
  // ----------------------------------------------------------
  if (payload.ver !== settings.token_version) {
    // Allow previous version during rotation window if explicitly configured
    const previousVersion = settings.token_version - 1;
    if (payload.ver !== previousVersion || previousVersion < 1) {
      throw new LicenseError(
        ErrorCode.TOKEN_VERSION_MISMATCH,
        'Token version is no longer supported. Please re-activate.',
        401
      );
    }
  }

  // ----------------------------------------------------------
  // Step 3: Expiration Check
  // ----------------------------------------------------------
  if (payload.exp !== null && payload.exp < now) {
    throw new LicenseError(
      ErrorCode.TOKEN_EXPIRED,
      'Activation token has expired.',
      401
    );
  }

  // ----------------------------------------------------------
  // Step 4: Device Binding Check (Timing-Safe)
  // ----------------------------------------------------------
  if (!constantTimeEquals(payload.device, deviceHash)) {
    throw new LicenseError(
      ErrorCode.DEVICE_MISMATCH,
      'Token does not belong to this device.',
      403
    );
  }

  // ----------------------------------------------------------
  // Step 5: Database State Check
  // ----------------------------------------------------------
  const license = await db.getLicenseByKey(env.DB, payload.license);
  
  if (!license) {
    throw new LicenseError(
      ErrorCode.LICENSE_NOT_FOUND,
      'License record no longer exists.',
      404
    );
  }

  if (license.status === LicenseStatus.REVOKED) {
    throw new LicenseError(
      ErrorCode.LICENSE_REVOKED,
      'License has been revoked since token issuance.',
      403
    );
  }

  if (license.status === LicenseStatus.EXPIRED || (license.expires_at !== null && license.expires_at < now)) {
    throw new LicenseError(
      ErrorCode.LICENSE_EXPIRED,
      'License has expired.',
      403
    );
  }

  // ----------------------------------------------------------
  // Step 6: Update Metrics
  // ----------------------------------------------------------
  await db.updateVerificationMetrics(env.DB, payload.license, deviceHash, now);

  return { status: license.status };
}

// ============================================================
// ADMIN OPERATION: GENERATE LICENSES
// ============================================================

export interface GenerateResult {
  generated: number;
  licenses: string[];
  plan: string;
  batchName: string;
}

/**
 * Generates a batch of cryptographically secure license keys.
 * Each key includes an embedded checksum for typo detection.
 */
export async function generateLicenses(
  env: Env,
  count: number,
  plan: string,
  batchName: string
): Promise<GenerateResult> {
  
  const now = nowSeconds();
  const licenses: string[] = [];
  
  // Generate keys (CPU-bound, fast for reasonable counts)
  for (let i = 0; i < count; i++) {
    licenses.push(generateLicenseKey());
  }
  
  // Batch insert into D1
  await db.batchInsertLicenses(env.DB, licenses, plan, batchName, now, env.APP_VERSION);
  
  return {
    generated: licenses.length,
    licenses,
    plan,
    batchName,
  };
}

// ============================================================
// ADMIN OPERATION: RESET
// ============================================================

/**
 * Resets a license to UNUSED state, detaching it from its device.
 * Allows the customer to activate on a new device.
 */
export async function resetLicense(env: Env, licenseKey: string): Promise<void> {
  const license = await db.getLicenseByKey(env.DB, licenseKey);
  
  if (!license) {
    throw new LicenseError(ErrorCode.LICENSE_NOT_FOUND, 'License does not exist.', 404);
  }
  
  if (license.status === LicenseStatus.REVOKED) {
    throw new LicenseError(
      ErrorCode.LICENSE_RESET_INVALID_STATE,
      'Cannot reset a revoked license. Unrevoke it first.',
      409
    );
  }

  await db.resetLicenseState(env.DB, licenseKey);
  await db.insertLog(env.DB, licenseKey, null, LogAction.RESET, 'SUCCESS', env.APP_VERSION);
}

// ============================================================
// ADMIN OPERATION: REVOKE
// ============================================================

/**
 * Permanently revokes a license with a recorded reason.
 * Future verifications will reject tokens issued for this license.
 */
export async function revokeLicense(
  env: Env,
  licenseKey: string,
  reason: string
): Promise<void> {
  const license = await db.getLicenseByKey(env.DB, licenseKey);
  
  if (!license) {
    throw new LicenseError(ErrorCode.LICENSE_NOT_FOUND, 'License does not exist.', 404);
  }

  await db.revokeLicenseState(env.DB, licenseKey, reason);
  await db.insertLog(env.DB, licenseKey, null, LogAction.REVOKED, 'SUCCESS', env.APP_VERSION);
}