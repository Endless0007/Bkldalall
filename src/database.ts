/**
 * ATOMIC ACTIVATION via D1 batch.
 * Guarantees that status change and device binding happen together.
 */
export async function atomicActivate(
  db: Env['DB'], licenseKey: string, deviceId: number, now: number
): Promise<boolean> {
  const result = await db.prepare(`
    UPDATE licenses 
    SET status = 'ACTIVE', device_id = ?, activated_at = ? 
    WHERE license_key = ? AND status = 'UNUSED'
  `).bind(deviceId, now, licenseKey).run();
  return result.meta.changes > 0;
}

/**
 * Updates verification timestamps for both license and device.
 */
export async function updateVerificationMetrics(
  db: Env['DB'], licenseKey: string, deviceHash: string, now: number
): Promise<void> {
  await db.batch([
    db.prepare('UPDATE licenses SET last_verified = ? WHERE license_key = ?').bind(now, licenseKey),
    db.prepare('UPDATE devices SET last_seen = ?, verification_count = verification_count + 1 WHERE device_hash = ?').bind(now, deviceHash),
  ]);
}

/**
 * Batch inserts generated licenses in a single round-trip.
 */
export async function batchInsertLicenses(
  db: Env['DB'], keys: string[], plan: string, batchName: string, now: number, workerVersion: string
): Promise<void> {
  const licenseStmts = keys.map(k =>
    db.prepare('INSERT INTO licenses (license_key, plan, created_at, created_by, batch_name) VALUES (?, ?, ?, ?, ?)')
      .bind(k, plan, now, 'admin', batchName)
  );
  const logStmts = keys.map(k =>
    db.prepare('INSERT INTO activation_logs (license_key, action, result, timestamp, worker_version) VALUES (?, ?, ?, ?, ?)')
      .bind(k, 'GENERATED', 'SUCCESS', now, workerVersion)
  );
  await db.batch([...licenseStmts, ...logStmts]);
}

/**
 * Resets license to UNUSED, clearing device binding.
 */
export async function resetLicenseState(db: Env['DB'], licenseKey: string): Promise<void> {
  await db.prepare(`
    UPDATE licenses SET status = 'UNUSED', device_id = NULL, activated_at = NULL, last_verified = NULL, revoked_reason = NULL
    WHERE license_key = ?
  `).bind(licenseKey).run();
}

/**
 * Revokes license with reason.
 */
export async function revokeLicenseState(db: Env['DB'], licenseKey: string, reason: string): Promise<void> {
  await db.prepare(`
    UPDATE licenses SET status = 'REVOKED', revoked_reason = ? WHERE license_key = ?
  `).bind(reason, licenseKey).run();
}