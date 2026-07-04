// src/index.ts

import { Env, ApiResponse, ActivationSuccessData, VerifySuccessData } from './types';
import { verifyAdminAuth, AuthError } from './auth';
import * as validator from './validator';
import * as license from './license';
import { ValidationError } from './validator';
import { LicenseError } from './license';
import * as db from './database';

// Maximum allowed request body size (2 KB)
const MAX_BODY_SIZE = 2048;

// ==========================================
// HTTP RESPONSE HELPERS
// ==========================================

function jsonResponse<T>(data: ApiResponse<T>, status: number = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store, max-age=0' // Prevent caching of licensing decisions
    },
  });
}

function successResponse<T>(data: T, version: string): Response {
  return jsonResponse<ApiResponse<T>>({
    success: true,
    data,
    backendVersion: version
  });
}

function errorResponse(code: string, status: number, version: string): Response {
  return jsonResponse<ApiResponse<null>>({
    success: false,
    code,
    backendVersion: version
  }, status);
}

// ==========================================
// ROUTE HANDLERS
// ==========================================

async function handleActivate(request: Request, env: Env): Promise<Response> {
  const rawBody = await request.text();
  if (rawBody.length > MAX_BODY_SIZE) {
    return errorResponse('PAYLOAD_TOO_LARGE', 413, env.APP_VERSION);
  }

  let body: any;
  try {
    body = JSON.parse(rawBody);
  } catch {
    return errorResponse('INVALID_JSON', 400, env.APP_VERSION);
  }

  const payload = validator.validateActivateRequest(body);
  const result = await license.activate(env, payload.license, payload.deviceHash, payload.appVersion);
  
  return successResponse<ActivationSuccessData>(result, env.APP_VERSION);
}

async function handleVerify(request: Request, env: Env): Promise<Response> {
  const rawBody = await request.text();
  if (rawBody.length > MAX_BODY_SIZE) {
    return errorResponse('PAYLOAD_TOO_LARGE', 413, env.APP_VERSION);
  }

  let body: any;
  try {
    body = JSON.parse(rawBody);
  } catch {
    return errorResponse('INVALID_JSON', 400, env.APP_VERSION);
  }

  const payload = validator.validateVerifyRequest(body);
  const result = await license.verify(env, payload.token, payload.deviceHash);
  
  return successResponse<VerifySuccessData>(result, env.APP_VERSION);
}

async function handleAdminGenerate(request: Request, env: Env): Promise<Response> {
  verifyAdminAuth(request, env);
  
  const rawBody = await request.text();
  if (rawBody.length > MAX_BODY_SIZE) return errorResponse('PAYLOAD_TOO_LARGE', 413, env.APP_VERSION);
  
  const body = JSON.parse(rawBody);
  const payload = validator.validateAdminGenerateRequest(body);
  
  const licenses = await license.generateLicenses(env, payload.count, payload.plan, payload.batchName);
  return successResponse({ generated: licenses.length, licenses }, env.APP_VERSION);
}

async function handleAdminReset(request: Request, env: Env): Promise<Response> {
  verifyAdminAuth(request, env);
  
  const rawBody = await request.text();
  if (rawBody.length > MAX_BODY_SIZE) return errorResponse('PAYLOAD_TOO_LARGE', 413, env.APP_VERSION);
  
  const body = JSON.parse(rawBody);
  const payload = validator.validateAdminResetRequest(body);
  
  await license.resetLicense(env, payload.license);
  return successResponse({ reset: true }, env.APP_VERSION);
}

async function handleAdminRevoke(request: Request, env: Env): Promise<Response> {
  verifyAdminAuth(request, env);
  
  const rawBody = await request.text();
  if (rawBody.length > MAX_BODY_SIZE) return errorResponse('PAYLOAD_TOO_LARGE', 413, env.APP_VERSION);
  
  const body = JSON.parse(rawBody);
  const payload = validator.validateAdminRevokeRequest(body);
  
  await license.revokeLicense(env, payload.license, payload.reason);
  return successResponse({ revoked: true }, env.APP_VERSION);
}

async function handleAdminHealth(env: Env): Promise<Response> {
  // Simple DB ping to ensure D1 is reachable
  await db.getSettings(env.DB);
  return successResponse({ status: 'OK', database: 'OK', worker: 'OK' }, env.APP_VERSION);
}

// ==========================================
// MAIN WORKER EXPORT
// ==========================================

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // 1. Enforce HTTPS and basic security headers
    const url = new URL(request.url);
    
    // Handle CORS preflight (Optional, but good if you ever build a web dashboard)
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Version',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    const version = env.APP_VERSION || '1.0.0';

    try {
      // 2. Routing
      if (url.pathname === '/activate' && request.method === 'POST') {
        return await handleActivate(request, env);
      }
      
      if (url.pathname === '/verify' && request.method === 'POST') {
        return await handleVerify(request, env);
      }

      if (url.pathname.startsWith('/admin/')) {
        if (url.pathname === '/admin/generate' && request.method === 'POST') {
          return await handleAdminGenerate(request, env);
        }
        if (url.pathname === '/admin/reset' && request.method === 'POST') {
          return await handleAdminReset(request, env);
        }
        if (url.pathname === '/admin/revoke' && request.method === 'POST') {
          return await handleAdminRevoke(request, env);
        }
        if (url.pathname === '/admin/health' && request.method === 'GET') {
          return await handleAdminHealth(env);
        }
        return errorResponse('ADMIN_ENDPOINT_NOT_FOUND', 404, version);
      }

      // 3. Fallback
      return errorResponse('NOT_FOUND', 404, version);

    } catch (error: any) {
      // 4. Global Error Handling (Fail Closed)
      
      if (error instanceof ValidationError) {
        return errorResponse('INVALID_REQUEST', 400, version);
      }
      
      if (error instanceof AuthError) {
        return errorResponse('UNAUTHORIZED', 401, version);
      }
      
      if (error instanceof LicenseError) {
        // Map specific business logic errors to HTTP statuses
        let status = 400;
        if (error.code === 'LICENSE_NOT_FOUND') status = 404;
        if (error.code === 'LICENSE_ALREADY_USED') status = 409;
        if (error.code === 'LICENSE_REVOKED') status = 403;
        if (error.code === 'MAINTENANCE') status = 503;
        
        return errorResponse(error.code, status, version);
      }

      // Catch-all for unexpected crashes (e.g., D1 outages, crypto failures)
      console.error('Unhandled Worker Exception:', error);
      return errorResponse('INTERNAL_ERROR', 500, version);
    }
  },
};