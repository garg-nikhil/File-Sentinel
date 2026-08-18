import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';

// --- SECURITY HEADERS MIDDLEWARE ---
export const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      connectSrc: ["'self'", "ws://localhost:3000", "ws://127.0.0.1:3000", "http://localhost:3000", "http://127.0.0.1:3000", "ws:", "wss:"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"]
    }
  },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  frameguard: { action: 'sameorigin' },
  hsts: process.env.NODE_ENV === 'production' ? { maxAge: 31536000, includeSubDomains: true } : false
});

// --- CORS MIDDLEWARE ---
export function corsMiddleware(req: Request, res: Response, next: NextFunction) {
  const origin = req.headers.origin;
  const allowedOrigins = [
    'http://localhost:3000',
    'http://127.0.0.1:3000'
  ];

  if (origin) {
    if (allowedOrigins.includes(origin) || origin.includes('.run.app') || origin.includes('ai.studio') || process.env.NODE_ENV !== 'production') {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-FS-IPC-Secret, X-CSRF-Token, X-Requested-With');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
}

// --- CONTENT-TYPE ENFORCEMENT ---
export function enforceContentType(req: Request, res: Response, next: NextFunction) {
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    const contentType = req.headers['content-type'];
    const contentLength = req.headers['content-length'];
    if (contentLength && parseInt(contentLength, 10) > 0) {
      if (!contentType || (!contentType.includes('application/json') && !contentType.includes('multipart/form-data'))) {
        return res.status(415).json({ error: 'Unsupported Media Type: Expected application/json' });
      }
    }
  }
  next();
}

// --- RATE LIMITER & PROGRESSIVE LOGIN THROTTLING ---
interface RateRecord {
  timestamps: number[];
}
const rateLimits = new Map<string, RateRecord>();

// Progressive login throttling / lockout store
interface LoginThrottleRecord {
  failedAttempts: number;
  lockoutUntil: number;
  lastAttempt: number;
}
const loginThrottleMap = new Map<string, LoginThrottleRecord>();

export function checkLoginThrottling(ipOrUsername: string): { allowed: boolean; remainingLockoutSeconds?: number; failedAttempts: number } {
  const now = Date.now();
  const record = loginThrottleMap.get(ipOrUsername);
  if (!record) {
    return { allowed: true, failedAttempts: 0 };
  }

  // If lockout expired, reset
  if (record.lockoutUntil > 0) {
    if (now < record.lockoutUntil) {
      const remainingSec = Math.ceil((record.lockoutUntil - now) / 1000);
      return { allowed: false, remainingLockoutSeconds: remainingSec, failedAttempts: record.failedAttempts };
    } else {
      // Lockout finished, decay attempts
      record.failedAttempts = Math.max(0, record.failedAttempts - 3);
      record.lockoutUntil = 0;
    }
  }

  // Decay stale attempts (after 15 minutes of inactivity)
  if (now - record.lastAttempt > 15 * 60 * 1000) {
    record.failedAttempts = 0;
  }

  return { allowed: true, failedAttempts: record.failedAttempts };
}

export function recordFailedLogin(ipOrUsername: string): { locked: boolean; lockoutSeconds: number; attempts: number } {
  const now = Date.now();
  let record = loginThrottleMap.get(ipOrUsername);
  if (!record) {
    record = { failedAttempts: 0, lockoutUntil: 0, lastAttempt: now };
    loginThrottleMap.set(ipOrUsername, record);
  }

  record.failedAttempts += 1;
  record.lastAttempt = now;

  let lockoutSeconds = 0;
  // Progressive backoff:
  // 5 failures -> 60s
  // 8 failures -> 300s (5 mins)
  // 12+ failures -> 900s (15 mins)
  if (record.failedAttempts >= 12) {
    lockoutSeconds = 900;
  } else if (record.failedAttempts >= 8) {
    lockoutSeconds = 300;
  } else if (record.failedAttempts >= 5) {
    lockoutSeconds = 60;
  }

  if (lockoutSeconds > 0) {
    record.lockoutUntil = now + lockoutSeconds * 1000;
    return { locked: true, lockoutSeconds, attempts: record.failedAttempts };
  }

  return { locked: false, lockoutSeconds: 0, attempts: record.failedAttempts };
}

export function recordSuccessfulLogin(ipOrUsername: string) {
  loginThrottleMap.delete(ipOrUsername);
}

export function rateLimiter(options: { windowMs: number; max: number; keyGenerator?: (req: Request) => string }) {
  return (req: Request, res: Response, next: NextFunction) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const key = options.keyGenerator ? options.keyGenerator(req) : `${ip}:${req.baseUrl || ''}${req.path}`;
    const now = Date.now();

    let record = rateLimits.get(key);
    if (!record) {
      record = { timestamps: [] };
      rateLimits.set(key, record);
    }

    // Filter out timestamps outside window
    record.timestamps = record.timestamps.filter(t => now - t < options.windowMs);

    if (record.timestamps.length >= options.max) {
      const retryAfter = Math.ceil((record.timestamps[0] + options.windowMs - now) / 1000);
      res.setHeader('Retry-After', String(Math.max(1, retryAfter)));
      return res.status(429).json({
        error: 'Too many requests, please try again later.',
        retry_after_seconds: Math.max(1, retryAfter)
      });
    }

    record.timestamps.push(now);
    next();
  };
}

// --- CSRF PROTECTION (Custom Header & Origin Validation) ---
export function csrfProtection(req: Request, res: Response, next: NextFunction) {
  // State-changing requests (POST, PUT, PATCH, DELETE) require either:
  // 1. Bearer token in Authorization header
  // 2. Custom header (X-Requested-With or X-CSRF-Token)
  // 3. Same-origin match
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    // Exempt webhooks (they use cryptographic HMAC-SHA256 signature verification)
    if (req.path.startsWith('/webhooks/') || req.path.startsWith('/api/webhooks/')) {
      return next();
    }

    const authHeader = req.headers['authorization'];
    const customHeader = req.headers['x-requested-with'] || req.headers['x-csrf-token'];
    const origin = req.headers['origin'];
    const host = req.headers['host'];

    // If bearer auth is present, CSRF is mitigated
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return next();
    }

    // If custom non-browser default header present, mitigate
    if (customHeader) {
      return next();
    }

    // Check origin vs host
    if (origin && host) {
      try {
        const originUrl = new URL(origin);
        if (originUrl.host === host) {
          return next();
        }
      } catch {}
    }

    // If none of the above and in production, reject
    if (process.env.NODE_ENV === 'production' && !authHeader) {
      return res.status(403).json({ error: 'Forbidden: Missing CSRF token or authorization header' });
    }
  }
  next();
}

// --- STRICT INPUT VALIDATORS ---
const FILE_ID_REGEX = /^FILE-[a-zA-Z0-9_-]{4,32}$/;
const SCAN_ID_REGEX = /^[a-zA-Z0-9_-]{4,64}$/;
const ORG_ID_REGEX = /^[a-zA-Z0-9_-]{3,64}$/;
const DEVICE_ID_REGEX = /^[a-zA-Z0-9_-]{3,64}$/;

export function isValidFileId(fileId: unknown): boolean {
  return typeof fileId === 'string' && FILE_ID_REGEX.test(fileId);
}

export function isValidScanId(scanId: unknown): boolean {
  return typeof scanId === 'string' && SCAN_ID_REGEX.test(scanId);
}

export function isValidOrgId(orgId: unknown): boolean {
  return typeof orgId === 'string' && ORG_ID_REGEX.test(orgId);
}

export function isValidDeviceId(deviceId: unknown): boolean {
  return typeof deviceId === 'string' && DEVICE_ID_REGEX.test(deviceId);
}

export function sanitizePagination(limit: any, offset: any): { limit: number; offset: number } {
  const parsedLimit = parseInt(limit, 10);
  const parsedOffset = parseInt(offset, 10);
  return {
    limit: isNaN(parsedLimit) || parsedLimit <= 0 ? 50 : Math.min(parsedLimit, 500),
    offset: isNaN(parsedOffset) || parsedOffset < 0 ? 0 : parsedOffset
  };
}

// --- SAFE ERROR HANDLER ---
export function safeErrorHandler(err: any, req: Request, res: Response, next: NextFunction) {
  console.error('[API Error]', {
    path: req.path,
    method: req.method,
    error: err.message,
    stack: process.env.NODE_ENV !== 'production' ? err.stack : undefined
  });

  // Strip stack traces, absolute paths, credentials, and internal details from client response
  const statusCode = err.status || err.statusCode || 500;
  let clientMessage = 'An internal server error occurred while processing the request.';

  if (err.code === 'LIMIT_FILE_SIZE' || err.message?.includes('RESOURCE_LIMIT_EXCEEDED')) {
    clientMessage = 'Resource limit exceeded for the requested operation.';
  } else if (err.message && (err.message.includes('not found') || err.message.includes('No such file'))) {
    clientMessage = 'Requested resource could not be found.';
  } else if (err.message && err.message.includes('validation')) {
    clientMessage = err.message;
  }

  res.status(statusCode).json({
    error: clientMessage,
    status: statusCode
  });
}
