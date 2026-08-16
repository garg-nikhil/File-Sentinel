import { getDatabase } from './db.js';
import crypto from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';

export type UserRole = 'SYS_ADMIN' | 'ORG_ADMIN' | 'AUDITOR' | 'OPERATOR' | 'VIEWER';

export interface AuthenticatedUser {
  userId: string;
  orgId: string;
  username: string;
  role: UserRole;
  deviceId?: string;
  sessionId: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
    }
  }
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  try {
    const [salt, key] = stored.split(':');
    if (!salt || !key) return false;
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(key, 'hex'), Buffer.from(hash, 'hex'));
  } catch {
    return false;
  }
}

export function logSecurityEvent(
  eventType: string,
  status: 'SUCCESS' | 'FAILURE',
  orgId?: string,
  userId?: string,
  deviceId?: string,
  details?: object,
  customDb?: any
) {
  try {
    const db = customDb || getDatabase();
    const id = crypto.randomUUID();
    const timestamp = new Date().toISOString();
    const detailsStr = details ? JSON.stringify(details) : null;
    db.prepare(`
      INSERT INTO security_audit_events (id, timestamp, event_type, org_id, user_id, device_id, details, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, timestamp, eventType, orgId || null, userId || null, deviceId || null, detailsStr, status);
  } catch (err) {
    console.error('[SecurityAudit] Failed to log event:', err);
  }
}

export function authenticateRequest(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.substring(7) : null;
  const deviceIdHeader = req.headers['x-device-id'] as string | undefined;

  const isDevMode = process.env.NODE_ENV !== 'production' && process.env.FILE_SENTINEL_DEV_MODE !== 'false';

  const activeDb = (req.app?.locals?.db) || getDatabase();

  if (!token) {
    if (isDevMode) {
      // In dev mode / tests, fallback to default local dev user & org & device
      const db = activeDb;
      let devOrg = db.prepare('SELECT org_id FROM organizations LIMIT 1').get() as { org_id: string } | undefined;
      let orgId = devOrg?.org_id;
      if (!orgId) {
        orgId = 'org-default-dev';
        db.prepare('INSERT OR IGNORE INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(orgId, 'Default Dev Organization', new Date().toISOString());
      }
      let devUser = db.prepare('SELECT user_id FROM users WHERE org_id = ? LIMIT 1').get(orgId) as { user_id: string } | undefined;
      let userId = devUser?.user_id;
      if (!userId) {
        userId = 'user-default-dev';
        const passwordHash = hashPassword('devpassword');
        db.prepare('INSERT OR IGNORE INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)').run(userId, orgId, 'devadmin', passwordHash, 'ORG_ADMIN', new Date().toISOString());
      }
      let devDevice = db.prepare('SELECT device_id FROM devices WHERE org_id = ? LIMIT 1').get(orgId) as { device_id: string } | undefined;
      let deviceId = devDevice?.device_id;
      if (!deviceId) {
        deviceId = 'dev-device-' + crypto.randomBytes(4).toString('hex');
        db.prepare('INSERT OR IGNORE INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 0, ?)').run(deviceId, orgId, 'Default Dev Device', new Date().toISOString());
      }

      req.user = {
        userId,
        orgId,
        username: 'devadmin',
        role: 'ORG_ADMIN',
        deviceId: deviceIdHeader || deviceId,
        sessionId: 'dev-session'
      };
      return next();
    }
    return res.status(401).json({ error: 'Unauthorized: Missing bearer token' });
  }

  try {
    const db = activeDb;
    const session = db.prepare(`
      SELECT s.token, s.user_id, s.org_id, s.device_id, s.expires_at,
             u.username, u.role, u.disabled,
             d.revoked as device_revoked
      FROM sessions s
      JOIN users u ON s.user_id = u.user_id
      LEFT JOIN devices d ON s.device_id = d.device_id
      WHERE s.token = ?
    `).get(token) as any;

    if (!session) {
      return res.status(401).json({ error: 'Unauthorized: Invalid session token' });
    }

    if (new Date(session.expires_at) < new Date()) {
      return res.status(401).json({ error: 'Unauthorized: Session expired' });
    }

    if (session.disabled === 1) {
      return res.status(403).json({ error: 'Forbidden: User account is disabled' });
    }

    if (session.device_revoked === 1) {
      return res.status(403).json({ error: 'Forbidden: Device registration has been revoked' });
    }

    req.user = {
      userId: session.user_id,
      orgId: session.org_id,
      username: session.username,
      role: session.role as UserRole,
      deviceId: session.device_id,
      sessionId: session.token
    };

    next();
  } catch (err: any) {
    console.error('[AuthMiddleware] Error:', err);
    return res.status(500).json({ error: 'Internal authentication error' });
  }
}

export function requireRole(allowedRoles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    if (!allowedRoles.includes(req.user.role)) {
      logSecurityEvent('AUTHORIZATION_FAILURE', 'FAILURE', req.user.orgId, req.user.userId, req.user.deviceId, { required: allowedRoles, actual: req.user.role });
      return res.status(403).json({ error: `Forbidden: Role '${req.user.role}' is not authorized for this action` });
    }
    next();
  };
}

export function verifyTenantAccess(targetOrgId: string, userOrgId: string): boolean {
  return targetOrgId === userOrgId;
}
