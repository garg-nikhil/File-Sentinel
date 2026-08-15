import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';

// --- SECURITY HEADERS MIDDLEWARE ---
export const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'", "ws:", "wss:"]
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
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
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

// --- RATE LIMITER (In-Memory sliding window for API abuse prevention) ---
interface RateRecord {
  timestamps: number[];
}
const rateLimits = new Map<string, RateRecord>();

export function rateLimiter(options: { windowMs: number; max: number }) {
  return (req: Request, res: Response, next: NextFunction) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const key = `${ip}:${req.path}`;
    const now = Date.now();

    let record = rateLimits.get(key);
    if (!record) {
      record = { timestamps: [] };
      rateLimits.set(key, record);
    }

    // Filter out timestamps outside window
    record.timestamps = record.timestamps.filter(t => now - t < options.windowMs);

    if (record.timestamps.length >= options.max) {
      return res.status(429).json({ error: 'Too many requests, please try again later.' });
    }

    record.timestamps.push(now);
    next();
  };
}

// --- VALIDATION HELPERS ---
const FILE_ID_REGEX = /^FILE-[a-zA-Z0-9_-]{4,32}$/;

export function isValidFileId(fileId: unknown): boolean {
  return typeof fileId === 'string' && FILE_ID_REGEX.test(fileId);
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
