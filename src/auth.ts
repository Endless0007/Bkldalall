// src/auth.ts

import { Env } from './types';

export class AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthError';
  }
}

/**
 * Verifies the Admin Secret from the Authorization header.
 * Expects: "Authorization: Bearer <ADMIN_SECRET>"
 * Uses constant-time comparison to prevent timing attacks.
 */
export function verifyAdminAuth(request: Request, env: Env): void {
  const authHeader = request.headers.get('Authorization');
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new AuthError('Missing or malformed Authorization header');
  }

  const providedSecret = authHeader.substring(7).trim();
  const expectedSecret = env.ADMIN_SECRET;

  if (!expectedSecret) {
    // This should never happen in production if secrets are configured correctly.
    throw new AuthError('Server misconfiguration: Admin secret missing');
  }

  // Constant-time comparison to prevent timing side-channel attacks
  if (providedSecret.length !== expectedSecret.length) {
    throw new AuthError('Invalid admin credentials');
  }

  let mismatch = 0;
  for (let i = 0; i < providedSecret.length; i++) {
    mismatch |= providedSecret.charCodeAt(i) ^ expectedSecret.charCodeAt(i);
  }

  if (mismatch !== 0) {
    throw new AuthError('Invalid admin credentials');
  }
}