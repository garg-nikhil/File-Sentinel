import express, { Request, Response } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import multer from 'multer';
import { getDatabase } from './db.js';
import { FileScannerEngine } from './scannerEngine.js';
import { getCloudStorageProvider } from './quarantineService.js';
import { analyzeContentWithGemini } from './gemini.js';
import { Rule, AppSettings, AuditEvent } from '../src/types.js';
import { EvidenceEngine } from './audit/evidenceEngine.js';
import { AuditReportGenerator } from './audit/auditReport.js';
import { INITIAL_AUDIT_CHECKLIST } from './audit/checklist.js';
import { AuditScoringEngine } from './audit/scoring.js';
import { isValidFileId, isValidScanId, isValidOrgId, isValidDeviceId, checkLoginThrottling, recordFailedLogin, recordSuccessfulLogin } from './securityMiddleware.js';
import { authenticateRequest, requireRole, hashPassword, verifyPassword, logSecurityEvent, UserRole } from './auth.js';
import { LicensingEngine, FeatureEntitlement } from './licensing.js';
import { TelemetryService } from './telemetry.js';
import { BillingService } from './billing.js';
import { PrivacyGovernanceService } from './privacyGovernance.js';
import { VerifiableAuditReportService } from './audit/verifiableReportService.js';
import { createAdminRouter } from './admin/adminRoutes.js';
import { PilotService } from './pilotService.js';

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Preserve relative directory structure if passed via originalname
    const relativePath = path.dirname(file.originalname);
    const uploadId = req.body.uploadId || 'default';
    const targetDir = path.join('backend', 'uploads', uploadId, relativePath);
    fs.mkdirSync(targetDir, { recursive: true });
    cb(null, targetDir);
  },
  filename: function (req, file, cb) {
    cb(null, path.basename(file.originalname));
  }
});
const uploadLocalScan = multer({ storage });

export function createApiRouter(customDb?: any) {
  const router = express.Router();
  const db = customDb || getDatabase();
  const scannerEngine = new FileScannerEngine(db);
  const cloudStorage = getCloudStorageProvider();
  const licensingEngine = new LicensingEngine(db);
  const telemetryService = new TelemetryService(db);
  const billingService = new BillingService(db, licensingEngine);
  const privacyGovernanceService = new PrivacyGovernanceService(db);
  const verifiableReportService = new VerifiableAuditReportService(db);

  router.use((req, res, next) => {
    if (req.app) {
      req.app.locals.db = db;
    }
    next();
  });

  // App Settings default state (Privacy-first defaults)
  let currentSettings: AppSettings = {
    maxFileSizeMB: 50,
    maxScanDepth: 10,
    aiEnabled: true,
    aiPrivacyMode: 'OFF',
    cloudUploadEnabled: false,
    telemetryEnabled: true,
    crashReportingEnabled: false,
    debugFilenamesEnabled: false,
    redactSensitivePreview: true,
    cloudBucketName: 'filesentinel-prod-quarantine',
    quarantineLocalDir: './storage_bucket/quarantine_staging',
    theme: 'midnight-emerald'
  };

  // Helper for audit logging
  function logAuditEvent(action: string, filePath?: string, sha256?: string, status: 'SUCCESS' | 'WARNING' | 'ERROR' = 'SUCCESS', details?: string) {
    try {
      const id = `AUDIT-${crypto.randomUUID().substring(0, 8)}`;
      const stmt = db.prepare(`
        INSERT INTO audit_events (id, timestamp, action, file_path, sha256, user_identity, status, details)
        VALUES (?, ?, ?, ?, ?, 'local-admin', ?, ?)
      `);
      stmt.run(id, new Date().toISOString(), action, filePath || null, sha256 || null, status, details || null);
    } catch (e) {
      console.error('Audit log write error:', e);
    }
  }

  function logSecEvent(eventType: string, status: 'SUCCESS' | 'FAILURE', orgId?: string, userId?: string, deviceId?: string, details?: object) {
    logSecurityEvent(eventType, status, orgId, userId, deviceId, details, db);
  }

  // --- AUTHENTICATION & IDENTITY ---
  router.post('/auth/login', (req: Request, res: Response) => {
    const { username, password, device_id } = req.body;
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || req.ip || 'unknown';
    const throttleKey = `${clientIp}:${username || 'anonymous'}`;

    // 1. Progressive throttling check
    const throttleCheck = checkLoginThrottling(throttleKey);
    if (!throttleCheck.allowed) {
      logSecEvent('LOGIN_LOCKED_OUT', 'FAILURE', undefined, undefined, device_id, {
        username,
        ip: clientIp,
        remaining_seconds: throttleCheck.remainingLockoutSeconds
      });
      res.setHeader('Retry-After', String(throttleCheck.remainingLockoutSeconds || 60));
      return res.status(429).json({
        error: `Account temporarily locked due to excessive failed attempts. Please retry after ${throttleCheck.remainingLockoutSeconds} seconds.`,
        retry_after_seconds: throttleCheck.remainingLockoutSeconds
      });
    }

    if (!username || !password) {
      recordFailedLogin(throttleKey);
      logSecEvent('LOGIN_FAILURE', 'FAILURE', undefined, undefined, device_id, { username, reason: 'missing_credentials' });
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username) as any;
    if (!user || user.disabled === 1 || !verifyPassword(password, user.password_hash)) {
      const failInfo = recordFailedLogin(throttleKey);
      logSecEvent('LOGIN_FAILURE', 'FAILURE', user?.org_id, user?.user_id, device_id, {
        username,
        reason: user?.disabled === 1 ? 'account_disabled' : 'invalid_credentials',
        failed_attempts: failInfo.attempts,
        locked: failInfo.locked
      });
      return res.status(401).json({
        error: 'Invalid username or password'
      });
    }

    if (device_id) {
      const device = db.prepare('SELECT * FROM devices WHERE device_id = ? AND org_id = ?').get(device_id, user.org_id) as any;
      if (!device || device.revoked === 1) {
        logSecEvent('LOGIN_FAILURE', 'FAILURE', user.org_id, user.user_id, device_id, { reason: 'device_revoked_or_unregistered' });
        return res.status(403).json({ error: 'Device is not registered or has been revoked' });
      }
    }

    // Reset throttle record upon success
    recordSuccessfulLogin(throttleKey);

    const token = 'tok-' + crypto.randomBytes(32).toString('hex');
    const refreshToken = 'rtk-' + crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(token, user.user_id, user.org_id, device_id || null, expiresAt, now);

    logSecEvent('LOGIN_SUCCESS', 'SUCCESS', user.org_id, user.user_id, device_id, { username });

    try {
      const pilotService = new PilotService(db);
      pilotService.recordTelemetry('dashboard_login', user.org_id, user.user_id, device_id, { username });
    } catch {}

    res.json({
      success: true,
      token,
      refresh_token: refreshToken,
      expires_at: expiresAt,
      refresh_expires_at: refreshExpiresAt,
      user: {
        user_id: user.user_id,
        org_id: user.org_id,
        username: user.username,
        role: user.role
      }
    });
  });

  // Token rotation & refresh endpoint
  router.post('/auth/rotate-token', authenticateRequest, (req: Request, res: Response) => {
    const oldSessionToken = req.user?.sessionId;
    if (!oldSessionToken || oldSessionToken === 'dev-session') {
      return res.json({ success: true, token: oldSessionToken, message: 'Dev session active' });
    }

    const newToken = 'tok-' + crypto.randomBytes(32).toString('hex');
    const newExpiresAt = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const now = new Date().toISOString();

    // Revoke old token and issue new token atomically
    db.prepare('DELETE FROM sessions WHERE token = ?').run(oldSessionToken);
    db.prepare(`
      INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(newToken, req.user!.userId, req.user!.orgId, req.user!.deviceId || null, newExpiresAt, now);

    logSecEvent('TOKEN_ROTATED', 'SUCCESS', req.user!.orgId, req.user!.userId, req.user!.deviceId);

    res.json({
      success: true,
      token: newToken,
      expires_at: newExpiresAt
    });
  });

  // Device token rotation
  router.post('/devices/:device_id/rotate-token', authenticateRequest, requireRole(['ORG_ADMIN', 'OPERATOR']), (req: Request, res: Response) => {
    const { device_id } = req.params;
    const orgId = req.user!.orgId;

    const device = db.prepare('SELECT * FROM devices WHERE device_id = ? AND org_id = ?').get(device_id, orgId) as any;
    if (!device) {
      return res.status(404).json({ error: 'Device not found in organization' });
    }
    if (device.revoked === 1) {
      return res.status(403).json({ error: 'Cannot rotate token on a revoked device' });
    }

    // Invalidate existing sessions for this device
    db.prepare('DELETE FROM sessions WHERE device_id = ?').run(device_id);

    const newDeviceToken = 'dtk-' + crypto.randomBytes(32).toString('hex');
    logSecEvent('DEVICE_TOKEN_ROTATED', 'SUCCESS', orgId, req.user!.userId, device_id);

    res.json({
      success: true,
      device_id,
      device_token: newDeviceToken,
      message: 'Device sessions invalidated and token rotated successfully.'
    });
  });

  // Invalidate all sessions for a user
  router.post('/users/:user_id/revoke-sessions', authenticateRequest, requireRole(['ORG_ADMIN']), (req: Request, res: Response) => {
    const { user_id } = req.params;
    const orgId = req.user!.orgId;

    const user = db.prepare('SELECT * FROM users WHERE user_id = ? AND org_id = ?').get(user_id, orgId) as any;
    if (!user) {
      return res.status(404).json({ error: 'User not found in organization' });
    }

    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user_id);
    logSecEvent('SESSIONS_REVOKED', 'SUCCESS', orgId, req.user!.userId, req.user!.deviceId, { target_user_id: user_id });

    res.json({ success: true, message: `All active sessions revoked for user ${user.username}` });
  });

  router.post('/auth/logout', authenticateRequest, (req: Request, res: Response) => {
    if (req.user?.sessionId && req.user.sessionId !== 'dev-session') {
      db.prepare('DELETE FROM sessions WHERE token = ?').run(req.user.sessionId);
    }
    res.json({ success: true });
  });

  router.get('/auth/me', authenticateRequest, (req: Request, res: Response) => {
    res.json(req.user);
  });

  // --- DEVICE & USER MANAGEMENT ---
  router.post('/devices/register', authenticateRequest, requireRole(['ORG_ADMIN']), (req: Request, res: Response) => {
    const { device_name } = req.body;
    if (!device_name) {
      return res.status(400).json({ error: 'Device name is required' });
    }
    const deviceId = 'dev-' + crypto.randomBytes(16).toString('hex');
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at)
      VALUES (?, ?, ?, 0, ?)
    `).run(deviceId, req.user!.orgId, device_name, now);

    logSecEvent('DEVICE_REGISTERED', 'SUCCESS', req.user!.orgId, req.user!.userId, deviceId, { device_name });
    res.json({ success: true, device_id: deviceId, device_name, org_id: req.user!.orgId });
  });

  router.post('/devices/:device_id/revoke', authenticateRequest, requireRole(['ORG_ADMIN']), (req: Request, res: Response) => {
    const { device_id } = req.params;
    const device = db.prepare('SELECT * FROM devices WHERE device_id = ? AND org_id = ?').get(device_id, req.user!.orgId) as any;
    if (!device) {
      return res.status(404).json({ error: 'Device not found in organization' });
    }
    db.prepare('UPDATE devices SET revoked = 1 WHERE device_id = ?').run(device_id);
    logSecEvent('DEVICE_REVOKED', 'SUCCESS', req.user!.orgId, req.user!.userId, device_id);
    res.json({ success: true, message: 'Device revoked successfully' });
  });

  router.post('/users/create', authenticateRequest, requireRole(['ORG_ADMIN']), (req: Request, res: Response) => {
    const { username, password, role } = req.body;
    if (!username || !password || !role) {
      return res.status(400).json({ error: 'Username, password, and role are required' });
    }
    const validRoles = ['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }
    const existing = db.prepare('SELECT user_id FROM users WHERE username = ?').get(username);
    if (existing) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const userId = 'usr-' + crypto.randomBytes(8).toString('hex');
    const passwordHash = hashPassword(password);
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at)
      VALUES (?, ?, ?, ?, ?, 0, ?)
    `).run(userId, req.user!.orgId, username, passwordHash, role, now);

    logSecEvent('USER_CREATED', 'SUCCESS', req.user!.orgId, req.user!.userId, req.user!.deviceId, { new_user_id: userId, username, role });
    res.json({ success: true, user_id: userId, username, role, org_id: req.user!.orgId });
  });

  router.post('/users/:user_id/toggle-disable', authenticateRequest, requireRole(['ORG_ADMIN']), (req: Request, res: Response) => {
    const { user_id } = req.params;
    const targetUser = db.prepare('SELECT * FROM users WHERE user_id = ? AND org_id = ?').get(user_id, req.user!.orgId) as any;
    if (!targetUser) {
      return res.status(404).json({ error: 'User not found in organization' });
    }
    const newDisabled = targetUser.disabled === 1 ? 0 : 1;
    db.prepare('UPDATE users SET disabled = ? WHERE user_id = ?').run(newDisabled, user_id);
    logSecEvent('USER_DISABLED', 'SUCCESS', req.user!.orgId, req.user!.userId, req.user!.deviceId, { target_user_id: user_id, disabled: newDisabled });
    res.json({ success: true, user_id, disabled: newDisabled });
  });

  router.post('/users/:user_id/role', authenticateRequest, requireRole(['ORG_ADMIN']), (req: Request, res: Response) => {
    const { user_id } = req.params;
    const { role } = req.body;
    const validRoles = ['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }
    const targetUser = db.prepare('SELECT * FROM users WHERE user_id = ? AND org_id = ?').get(user_id, req.user!.orgId) as any;
    if (!targetUser) {
      return res.status(404).json({ error: 'User not found in organization' });
    }
    db.prepare('UPDATE users SET role = ? WHERE user_id = ?').run(role, user_id);
    logSecEvent('ROLE_CHANGED', 'SUCCESS', req.user!.orgId, req.user!.userId, req.user!.deviceId, { target_user_id: user_id, new_role: role });
    res.json({ success: true, user_id, role });
  });

  router.delete('/users/:user_id', authenticateRequest, requireRole(['ORG_ADMIN']), (req: Request, res: Response) => {
    const { user_id } = req.params;
    if (user_id === req.user!.userId) {
      return res.status(400).json({ error: 'Cannot remove your own active administrator account' });
    }
    const targetUser = db.prepare('SELECT * FROM users WHERE user_id = ? AND org_id = ?').get(user_id, req.user!.orgId) as any;
    if (!targetUser) {
      return res.status(404).json({ error: 'User not found in organization' });
    }
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user_id);
    db.prepare('DELETE FROM users WHERE user_id = ? AND org_id = ?').run(user_id, req.user!.orgId);
    logSecEvent('USER_REMOVED', 'SUCCESS', req.user!.orgId, req.user!.userId, req.user!.deviceId, { target_user_id: user_id, username: targetUser.username });
    res.json({ success: true, user_id, message: 'User removed successfully' });
  });

  router.get('/users', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    const rows = db.prepare(`
      SELECT user_id, org_id, username, role, disabled, created_at
      FROM users
      WHERE org_id = ?
      ORDER BY created_at ASC
    `).all(orgId);
    res.json(rows);
  });

  router.get('/devices', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    // Join with license_devices and scan_telemetry to get OS, version, last seen, and license status
    const devices = db.prepare(`
      SELECT d.device_id, d.org_id, d.device_name, d.revoked, d.registered_at
      FROM devices d
      WHERE d.org_id = ?
      ORDER BY d.registered_at DESC
    `).all(orgId) as any[];

    const enriched = devices.map(d => {
      const latestScan = db.prepare(`
        SELECT completed_at, started_at, application_version, device_telemetry_json
        FROM scan_telemetry
        WHERE organization_id = ? AND device_id = ?
        ORDER BY started_at DESC
        LIMIT 1
      `).get(orgId, d.device_id) as any;

      const licDevice = db.prepare(`
        SELECT status, last_seen_at FROM license_devices WHERE device_id = ?
      `).get(d.device_id) as any;

      let osInfo = 'Linux';
      let appVersion = '1.0.0';
      if (latestScan?.device_telemetry_json) {
        try {
          const devTel = JSON.parse(latestScan.device_telemetry_json);
          osInfo = `${devTel.os_family || 'OS'} ${devTel.os_version || ''} (${devTel.architecture || ''})`.trim();
          appVersion = devTel.filesentinel_version || latestScan.application_version || '1.0.0';
        } catch {}
      }

      return {
        device_id: d.device_id,
        device_name: d.device_name,
        org_id: d.org_id,
        revoked: Boolean(d.revoked),
        registered_at: d.registered_at,
        os: osInfo,
        application_version: latestScan?.application_version || appVersion,
        last_seen: latestScan?.completed_at || latestScan?.started_at || licDevice?.last_seen_at || d.registered_at,
        license_status: d.revoked ? 'REVOKED' : (licDevice?.status === 'ACTIVE' ? 'ACTIVE' : 'UNLICENSED')
      };
    });

    res.json(enriched);
  });

  router.post('/organizations/create', authenticateRequest, requireRole(['ORG_ADMIN']), (req: Request, res: Response) => {
    const { name } = req.body;
    if (!name) {
      return res.status(400).json({ error: 'Organization name is required' });
    }
    const orgId = 'org-' + crypto.randomBytes(8).toString('hex');
    const now = new Date().toISOString();
    db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(orgId, name, now);
    logSecurityEvent('ORGANIZATION_CREATED', 'SUCCESS', orgId, req.user!.userId, req.user!.deviceId, { name });
    res.json({ success: true, org_id: orgId, name });
  });

  // --- CUSTOMER / VENDOR LICENSING ENDPOINTS ---
  router.get('/license', authenticateRequest, (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    const deviceId = req.user!.deviceId;
    const clientReportedTime = req.headers['x-client-timestamp'] as string | undefined;

    const validation = licensingEngine.validateLicense(orgId, {
      deviceId,
      clientReportedTime,
      actorId: req.user!.userId
    });

    const license = licensingEngine.getLicenseForOrg(orgId);

    res.json({
      ...validation,
      plan_name: license?.plan_id,
      issued_at: license?.issued_at,
      starts_at: license?.starts_at,
      expires_at: license?.expires_at,
      grace_until: license?.grace_until,
      max_users: license?.max_users,
      max_devices: license?.max_devices,
      scan_limit: license?.scan_limit,
      scans_used: license?.scans_used,
      feature_flags: license?.feature_flags
    });
  });

  router.get('/license/devices', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    const license = licensingEngine.getLicenseForOrg(orgId);
    if (!license) return res.status(404).json({ error: 'No license found for organization' });

    const rows = db.prepare(`
      SELECT ld.*, d.device_name, d.registered_at, d.revoked
      FROM license_devices ld
      JOIN devices d ON ld.device_id = d.device_id
      WHERE ld.license_id = ? AND d.org_id = ?
      ORDER BY ld.activated_at DESC
    `).all(license.license_id, orgId);

    res.json(rows);
  });

  router.post('/license/devices/activate', authenticateRequest, requireRole(['ORG_ADMIN']), (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    const { device_id } = req.body;
    const targetDeviceId = device_id || req.user!.deviceId;
    if (!targetDeviceId) return res.status(400).json({ error: 'device_id is required' });

    const license = licensingEngine.getLicenseForOrg(orgId);
    if (!license) return res.status(404).json({ error: 'No license found for organization' });

    const result = licensingEngine.activateDevice(license.license_id, orgId, targetDeviceId, req.user!.userId);
    if (!result.success) {
      return res.status(400).json({ error: result.message });
    }
    res.json(result);
  });

  router.post('/license/devices/deactivate', authenticateRequest, requireRole(['ORG_ADMIN']), (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    const { device_id } = req.body;
    if (!device_id) return res.status(400).json({ error: 'device_id is required' });

    const license = licensingEngine.getLicenseForOrg(orgId);
    if (!license) return res.status(404).json({ error: 'No license found for organization' });

    const result = licensingEngine.deactivateDevice(license.license_id, orgId, device_id, req.user!.userId);
    if (!result.success) {
      return res.status(400).json({ error: result.message });
    }
    res.json(result);
  });

  router.get('/license/events', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR']), (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    const rows = db.prepare(`
      SELECT * FROM license_events 
      WHERE org_id = ? 
      ORDER BY timestamp DESC 
      LIMIT 100
    `).all(orgId) as any[];

    res.json(rows.map(r => ({
      ...r,
      details: r.details ? JSON.parse(r.details) : null
    })));
  });

  // --- HEALTH & METRICS ---
  router.get('/health', (req: Request, res: Response) => {
    res.json({
      status: 'ok',
      service: 'FileSentinel Engine',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      database: 'connected'
    });
  });

  router.get('/settings', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    res.json(currentSettings);
  });

  router.post('/settings', authenticateRequest, requireRole(['ORG_ADMIN']), (req: Request, res: Response) => {
    currentSettings = { ...currentSettings, ...req.body };
    logAuditEvent('UPDATE_SETTINGS', undefined, undefined, 'SUCCESS', 'App configuration updated');
    res.json(currentSettings);
  });

  // --- PRIVACY-FIRST DATA GOVERNANCE & TELEMETRY DEBUGGER ---
  router.get('/privacy/governance', (req: Request, res: Response) => {
    try {
      const manifest = privacyGovernanceService.getGovernanceManifest();
      res.json(manifest);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/privacy/telemetry-preview/:scan_id', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    try {
      const { scan_id } = req.params;
      const orgId = req.user!.orgId;
      const userId = req.user!.userId;
      const deviceId = req.user!.deviceId || 'dev-local-station';

      // Tenant isolation: verify scan belongs to this org if org_id is present
      const scanRow = db.prepare('SELECT * FROM scans WHERE scan_id = ?').get(scan_id) as any;
      if (!scanRow) {
        return res.status(404).json({ error: 'Scan session not found' });
      }
      if (scanRow.org_id && scanRow.org_id !== orgId) {
        return res.status(403).json({ error: 'Access denied: Cross-tenant telemetry inspection forbidden' });
      }

      const inspection = privacyGovernanceService.inspectScanTelemetryPayload(
        scan_id,
        orgId,
        userId,
        deviceId,
        {
          telemetryEnabled: currentSettings.telemetryEnabled,
          debugFilenamesEnabled: currentSettings.debugFilenamesEnabled
        }
      );

      res.json(inspection);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/privacy/retention-policy', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const policy = privacyGovernanceService.getRetentionPolicy(orgId);
      res.json(policy);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/privacy/retention-policy', authenticateRequest, requireRole(['ORG_ADMIN']), (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const { cloud_metadata_retention_days, auto_purge_enabled } = req.body;
      if (cloud_metadata_retention_days === undefined || typeof cloud_metadata_retention_days !== 'number') {
        return res.status(400).json({ error: 'cloud_metadata_retention_days number is required (30, 90, 180, 365, or -1)' });
      }

      const policy = privacyGovernanceService.setRetentionPolicy(orgId, cloud_metadata_retention_days, auto_purge_enabled !== false);
      logAuditEvent('UPDATE_RETENTION_POLICY', undefined, undefined, 'SUCCESS', `Retention policy set to ${cloud_metadata_retention_days} days for ${orgId}`);
      res.json({ success: true, policy });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/privacy/purge-cloud-telemetry', authenticateRequest, requireRole(['ORG_ADMIN']), (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const result = privacyGovernanceService.purgeExpiredCloudTelemetry(orgId);
      logAuditEvent('PURGE_CLOUD_TELEMETRY', undefined, undefined, 'SUCCESS', `Purged ${result.purged_telemetry_records} telemetry rows under ${result.retention_days}-day policy. Local data preserved.`);
      res.json({ success: true, ...result });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // --- SCANS ---
  router.post('/scans/upload-target', authenticateRequest, requireRole(['ORG_ADMIN', 'OPERATOR']), uploadLocalScan.array('files'), (req: Request, res: Response) => {
    const uploadId = req.body.uploadId;
    if (!uploadId) {
      return res.status(400).json({ error: 'Missing uploadId' });
    }
    const uploadedPath = path.resolve(path.join('backend', 'uploads', uploadId));
    const files = req.files as any[] || [];
    res.json({ success: true, root_path: uploadedPath, file_count: files.length });
  });

  router.post('/scans', authenticateRequest, requireRole(['ORG_ADMIN', 'OPERATOR']), async (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    const userId = req.user!.userId;
    const deviceId = req.user!.deviceId;
    const { root_path, root_paths } = req.body;
    const pathsToScan = root_paths || (root_path ? [root_path] : []);
    const validPaths: string[] = [];

    for (const rawPath of pathsToScan) {
      if (!rawPath || typeof rawPath !== 'string' || !rawPath.trim()) continue;
      const targetPath = path.resolve(rawPath.trim());
      try {
        if (!fs.existsSync(targetPath)) {
          return res.status(400).json({ error: `Directory target does not exist: ${targetPath}` });
        }
        const realTarget = fs.realpathSync(targetPath);
        const baseAllowed = process.env.BASE_ALLOWED_DIR ? fs.realpathSync(process.env.BASE_ALLOWED_DIR) : null;
        if (baseAllowed) {
          const rel = path.relative(baseAllowed, realTarget);
          if (rel === '..' || rel.startsWith('..' + path.sep) || rel.startsWith('../') || rel.startsWith('..\\') || path.isAbsolute(rel)) {
            return res.status(403).json({ error: `Access denied: Requested path is outside allowed directory.` });
          }
        }
        validPaths.push(targetPath);
      } catch (e: any) {
        return res.status(400).json({ error: `Directory target cannot be resolved: ${targetPath}` });
      }
    }

    if (validPaths.length === 0) {
      return res.status(400).json({ error: 'Please specify target directory paths or upload a folder.' });
    }

    // 1. Licensing Engine Pre-Scan Enforcement
    const licenseValidation = licensingEngine.validateLicense(orgId, {
      deviceId,
      requiredFeature: 'LOCAL_SCANNING',
      isStartingScan: true,
      actorId: userId
    });

    if (!licenseValidation.valid) {
      return res.status(403).json({
        error: licenseValidation.error || 'License validation failed',
        ui_state: licenseValidation.ui_state,
        status: licenseValidation.status
      });
    }

    // Multi-folder scanning feature entitlement check
    if (validPaths.length > 1) {
      const multiFolderCheck = licensingEngine.validateLicense(orgId, {
        deviceId,
        requiredFeature: 'MULTI_FOLDER_SCAN',
        actorId: userId
      });
      if (!multiFolderCheck.valid) {
        return res.status(403).json({
          error: multiFolderCheck.error || 'Multi-folder scanning requires an upgraded license plan',
          ui_state: multiFolderCheck.ui_state,
          status: multiFolderCheck.status
        });
      }
    }

    // Fetch active rules from DB
    const rows = db.prepare('SELECT * FROM rules WHERE enabled = 1').all() as any[];
    const activeRules: Rule[] = rows.map(r => ({
      id: r.id,
      name: r.name,
      category: r.category,
      severity: r.severity,
      enabled: Boolean(r.enabled),
      pattern: r.pattern,
      description: r.description,
      recommendation: r.recommendation,
      isBuiltIn: Boolean(r.is_builtin)
    }));

    // Consume scan quota atomically
    if (licenseValidation.license_id) {
      licensingEngine.consumeScanQuota(licenseValidation.license_id, 1);
    }

    const session = await scannerEngine.startScan(validPaths, activeRules, currentSettings, orgId, userId, deviceId);
    logAuditEvent('START_SCAN', validPaths.join(', '), undefined, 'SUCCESS', `Scan ID: ${session.scan_id}`);

    res.json(session);
  });

  router.get('/scans', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    const rows = db.prepare('SELECT * FROM scans WHERE org_id = ? OR org_id IS NULL ORDER BY start_time DESC LIMIT 50').all(orgId);
    res.json(rows);
  });

  // --- TELEMETRY & PRIVACY-PRESERVING SCAN HISTORY ---
  router.post('/telemetry/scans', authenticateRequest, requireRole(['ORG_ADMIN', 'OPERATOR', 'AUDITOR']), (req: Request, res: Response) => {
    const authOrgId = req.user!.orgId;
    const authUserId = req.user!.userId;
    const authDeviceId = req.user!.deviceId || 'dev-default';
    const payload = req.body;

    if (!payload || typeof payload !== 'object') {
      return res.status(400).json({ error: 'Invalid scan telemetry payload structure' });
    }

    // Forgery prevention: Forged organization_id
    if (payload.organization_id && payload.organization_id !== authOrgId) {
      logSecEvent('TELEMETRY_FORGERY_ATTEMPT', 'FAILURE', authOrgId, authUserId, authDeviceId, {
        reason: 'forged_organization_id',
        attempted_org: payload.organization_id
      });
      return res.status(403).json({ error: 'Tenant authorization violation: Forged organization_id detected' });
    }

    // Forgery prevention: Forged user_id
    if (payload.user_id && payload.user_id !== authUserId) {
      logSecEvent('TELEMETRY_FORGERY_ATTEMPT', 'FAILURE', authOrgId, authUserId, authDeviceId, {
        reason: 'forged_user_id',
        attempted_user: payload.user_id
      });
      return res.status(403).json({ error: 'User authorization violation: Forged user_id detected' });
    }

    // Bind authenticated credentials
    payload.organization_id = authOrgId;
    payload.user_id = authUserId;
    payload.device_id = payload.device_id || authDeviceId;

    try {
      const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || req.ip;
      const result = telemetryService.recordScanTelemetry(payload, clientIp);
      return res.json(result);
    } catch (err: any) {
      return res.status(400).json({ error: err.message || 'Failed to record telemetry payload' });
    }
  });

  router.get('/scans/history', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    const limit = parseInt(req.query.limit as string) || 50;
    const offset = parseInt(req.query.offset as string) || 0;
    const history = telemetryService.getScanHistory(orgId, limit, offset);
    res.json(history);
  });

  router.get('/scans/:id', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    const { id } = req.params;
    const orgId = req.user!.orgId;
    const active = scannerEngine.getScanProgress(id);
    if (active) {
      const rowDb = db.prepare('SELECT org_id FROM scans WHERE scan_id = ?').get(id) as any;
      if (rowDb && rowDb.org_id && rowDb.org_id !== orgId) {
        return res.status(403).json({ error: 'Access denied: Cross-tenant scan access forbidden' });
      }
      return res.json(active);
    }

    // Check scans table
    const row = db.prepare('SELECT * FROM scans WHERE scan_id = ? AND (org_id = ? OR org_id IS NULL)').get(id, orgId);
    if (row) {
      return res.json(row);
    }

    // Check scan_telemetry table
    const telemetryRow = telemetryService.getScanTelemetry(orgId, id);
    if (telemetryRow) {
      return res.json(telemetryRow);
    }

    // Cross-tenant check for telemetry
    const crossCheck = db.prepare('SELECT organization_id FROM scan_telemetry WHERE scan_id = ?').get(id) as any;
    if (crossCheck && crossCheck.organization_id !== orgId) {
      return res.status(403).json({ error: 'Access denied: Cross-tenant scan access forbidden' });
    }

    res.status(404).json({ error: 'Scan session not found or unauthorized' });
  });

  router.post('/telemetry/queue/flush', authenticateRequest, requireRole(['ORG_ADMIN', 'OPERATOR']), (req: Request, res: Response) => {
    try {
      const result = telemetryService.flushQueue();
      res.json({ success: true, ...result });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to flush telemetry queue' });
    }
  });

  router.get('/telemetry/queue/status', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    const stats = telemetryService.getQueueStatus(orgId);
    res.json(stats);
  });

  // --- VENDOR CLOUD DASHBOARD ENDPOINTS ---
  router.get('/cloud-dashboard/overview', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    const overview = telemetryService.getDashboardOverview(orgId);
    res.json(overview);
  });

  router.get('/cloud-dashboard/trend', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    const limit = parseInt(req.query.limit as string) || 30;
    const trend = telemetryService.getComplianceTrend(orgId, limit);
    res.json(trend);
  });

  router.post('/cloud-dashboard/verify-report', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    const { query_id } = req.body;
    if (!query_id || typeof query_id !== 'string') {
      return res.status(400).json({ error: 'query_id parameter is required for report verification' });
    }
    const result = telemetryService.verifyReport(orgId, query_id);
    res.json(result);
  });

  router.get('/cloud-dashboard/organization', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    const org = db.prepare('SELECT org_id, name, created_at FROM organizations WHERE org_id = ?').get(orgId) as any;
    const license = licensingEngine.getLicenseForOrg(orgId);
    const validation = licensingEngine.validateLicense(orgId, { actorId: req.user!.userId });

    // Usage statistics
    const userCount = (db.prepare('SELECT COUNT(*) as count FROM users WHERE org_id = ?').get(orgId) as any)?.count || 0;
    const deviceCount = (db.prepare('SELECT COUNT(*) as count FROM devices WHERE org_id = ?').get(orgId) as any)?.count || 0;
    const activeDeviceCount = (db.prepare('SELECT COUNT(*) as count FROM devices WHERE org_id = ? AND revoked = 0').get(orgId) as any)?.count || 0;
    const scanCount = (db.prepare('SELECT COUNT(*) as count FROM scan_telemetry WHERE organization_id = ?').get(orgId) as any)?.count || 0;

    res.json({
      organization_id: orgId,
      organization_name: org?.name || 'My Organization',
      created_at: org?.created_at,
      plan: license?.plan_id || 'COMMUNITY_TRIAL',
      license_status: validation.status,
      ui_state: validation.ui_state,
      license_valid: validation.valid,
      expires_at: license?.expires_at,
      grace_until: license?.grace_until,
      usage: {
        users: {
          current: userCount,
          max: license?.max_users || 5
        },
        devices: {
          current: activeDeviceCount,
          total_registered: deviceCount,
          max: license?.max_devices || 3
        },
        scans: {
          used: license?.scans_used || scanCount,
          limit: license?.scan_limit || 100
        }
      }
    });
  });

  router.get('/cloud-dashboard/software-version', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    const currentVersion = '1.0.0';
    const latestAvailableVersion = '1.0.0';
    const checklistVersion = '2026.1';
    res.json({
      current_version: currentVersion,
      latest_version: latestAvailableVersion,
      checklist_version: checklistVersion,
      update_available: currentVersion !== latestAvailableVersion,
      channel: 'production-stable',
      engine: 'FileSentinel Local-First Deterministic Engine',
      release_date: '2026-08-15'
    });
  });

  // --- COMMERCIALIZATION PHASE 5: SUBSCRIPTION BILLING & WEBHOOKS ---
  router.get('/billing/state', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const billingState = billingService.getOrganizationBillingState(orgId);
      res.json(billingState);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to retrieve billing state' });
    }
  });

  router.get('/billing/plans', (req: Request, res: Response) => {
    try {
      const plans = billingService.getAllPlans();
      res.json(plans);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/billing/checkout', authenticateRequest, requireRole(['ORG_ADMIN']), (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const { plan_key, interval, email } = req.body;
      if (!plan_key || !['TRIAL', 'PROFESSIONAL', 'ENTERPRISE'].includes(plan_key.toUpperCase())) {
        return res.status(400).json({ error: 'plan_key must be one of: TRIAL, PROFESSIONAL, ENTERPRISE' });
      }

      const userEmail = email || (db.prepare('SELECT username FROM users WHERE user_id = ?').get(req.user!.userId) as any)?.username + '@filesentinel.local';
      const checkout = billingService.createSubscriptionCheckout(
        orgId,
        userEmail,
        plan_key.toUpperCase() as any,
        interval === 'ANNUAL' ? 'ANNUAL' : 'MONTHLY'
      );

      res.json({ success: true, ...checkout });
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  router.post('/billing/change-plan', authenticateRequest, requireRole(['ORG_ADMIN']), (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const { new_plan_key, interval } = req.body;
      if (!new_plan_key || !['TRIAL', 'PROFESSIONAL', 'ENTERPRISE'].includes(new_plan_key.toUpperCase())) {
        return res.status(400).json({ error: 'new_plan_key must be one of: TRIAL, PROFESSIONAL, ENTERPRISE' });
      }

      const result = billingService.changeSubscriptionPlan(
        orgId,
        new_plan_key.toUpperCase() as any,
        interval === 'ANNUAL' ? 'ANNUAL' : 'MONTHLY'
      );

      res.json(result);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  router.post('/billing/cancel', authenticateRequest, requireRole(['ORG_ADMIN']), (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const sub = db.prepare('SELECT * FROM subscriptions WHERE org_id = ? ORDER BY created_at DESC LIMIT 1').get(orgId) as any;
      if (!sub) {
        return res.status(404).json({ error: 'No active subscription found for organization' });
      }

      const nowIso = new Date().toISOString();
      db.prepare(`
        UPDATE subscriptions SET
          status = 'CANCELLED',
          cancelled_at = ?,
          updated_at = ?
        WHERE subscription_id = ?
      `).run(nowIso, nowIso, sub.subscription_id);

      billingService.logSubscriptionEvent(sub.subscription_id, orgId, 'SUBSCRIPTION_CANCELLED_MANUALLY', sub.status, 'CANCELLED', { actor_id: req.user!.userId });
      licensingEngine.updateLicenseStatus(sub.org_id, 'CANCELLED', { reason: 'User requested cancellation' }, req.user!.userId);

      res.json({ success: true, message: 'Subscription cancelled successfully' });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Razorpay Webhook Ingestion Endpoint (Authoritative server-side event processor)
  router.post('/webhooks/razorpay', express.raw({ type: 'application/json' }), (req: Request, res: Response) => {
    try {
      const signature = req.headers['x-razorpay-signature'] as string;
      if (!signature) {
        return res.status(400).json({ error: 'Missing x-razorpay-signature header' });
      }

      let rawBody = '';
      let parsedPayload: any = null;

      if (Buffer.isBuffer(req.body)) {
        rawBody = req.body.toString('utf-8');
        parsedPayload = JSON.parse(rawBody);
      } else if (typeof req.body === 'string') {
        rawBody = req.body;
        parsedPayload = JSON.parse(rawBody);
      } else {
        parsedPayload = req.body;
        rawBody = JSON.stringify(req.body);
      }

      const eventId = parsedPayload.id || parsedPayload.event_id || (parsedPayload.payload?.payment?.entity?.id ? `evt_${parsedPayload.event}_${parsedPayload.payload.payment.entity.id}` : `evt_${crypto.randomBytes(8).toString('hex')}`);

      const result = billingService.processWebhook(eventId, rawBody, signature, parsedPayload);
      res.json(result);
    } catch (err: any) {
      res.status(400).json({ error: err.message || 'Webhook verification failed' });
    }
  });

  router.get('/scans/:id/progress', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    const { id } = req.params;
    const orgId = req.user!.orgId;
    const active = scannerEngine.getScanProgress(id);
    if (active) {
      const rowDb = db.prepare('SELECT org_id FROM scans WHERE scan_id = ?').get(id) as any;
      if (rowDb && rowDb.org_id && rowDb.org_id !== orgId) {
        return res.status(403).json({ error: 'Access denied: Cross-tenant scan progress forbidden' });
      }
      return res.json(active);
    }

    const row = db.prepare('SELECT * FROM scans WHERE scan_id = ? AND (org_id = ? OR org_id IS NULL)').get(id, orgId) as any;
    if (!row) return res.status(404).json({ error: 'Scan session not found or unauthorized' });
    res.json(row);
  });

  // --- FILES ---
  router.get('/files', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    const { scan_id, classification, severity } = req.query;
    let query = 'SELECT f.* FROM files f JOIN scans s ON f.scan_id = s.scan_id WHERE (s.org_id = ? OR s.org_id IS NULL)';
    const params: any[] = [orgId];
    const conditions: string[] = [];

    if (scan_id) {
      const scanRow = db.prepare('SELECT org_id FROM scans WHERE scan_id = ?').get(scan_id) as any;
      if (scanRow && scanRow.org_id && scanRow.org_id !== orgId) {
        return res.status(403).json({ error: 'Access denied: Cross-tenant file access forbidden' });
      }
      conditions.push('f.scan_id = ?');
      params.push(scan_id);
    }
    if (classification) {
      conditions.push('f.classification = ?');
      params.push(classification);
    }

    if (conditions.length > 0) {
      query += ' AND ' + conditions.join(' AND ');
    }

    query += ' ORDER BY f.risk_score DESC, f.file_id DESC LIMIT 200';

    const rows = db.prepare(query).all(...params) as any[];
    const parsedFiles = rows.map(f => {
      const findingsRows = db.prepare('SELECT * FROM findings WHERE file_id = ?').all(f.file_id) as any[];
      const findings = findingsRows.map(fRow => ({
        ...fRow,
        evidence: fRow.evidence_json ? JSON.parse(fRow.evidence_json) : {}
      }));

      const findings_count = {
        critical: findings.filter(x => x.severity === 'CRITICAL').length,
        high: findings.filter(x => x.severity === 'HIGH').length,
        medium: findings.filter(x => x.severity === 'MEDIUM').length,
        low: findings.filter(x => x.severity === 'LOW').length,
        info: findings.filter(x => x.severity === 'INFO').length
      };

      return {
        ...f,
        findings,
        findings_count,
        metadata: f.metadata_json ? JSON.parse(f.metadata_json) : {},
        warnings: f.warnings_json ? JSON.parse(f.warnings_json) : [],
        ai_summary: f.ai_summary_json ? JSON.parse(f.ai_summary_json) : undefined
      };
    });

    res.json(parsedFiles);
  });

  router.get('/files/:id', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    const { id } = req.params;
    const orgId = req.user!.orgId;
    const row = db.prepare(`
      SELECT f.* FROM files f
      JOIN scans s ON f.scan_id = s.scan_id
      WHERE f.file_id = ? AND (s.org_id = ? OR s.org_id IS NULL)
    `).get(id, orgId) as any;
    if (!row) return res.status(404).json({ error: 'File not found or unauthorized' });

    const findingsRows = db.prepare('SELECT * FROM findings WHERE file_id = ?').all(id) as any[];
    const findings = findingsRows.map(fRow => ({
      ...fRow,
      evidence: fRow.evidence_json ? JSON.parse(fRow.evidence_json) : {}
    }));

    res.json({
      ...row,
      findings,
      metadata: row.metadata_json ? JSON.parse(row.metadata_json) : {},
      warnings: row.warnings_json ? JSON.parse(row.warnings_json) : [],
      ai_summary: row.ai_summary_json ? JSON.parse(row.ai_summary_json) : undefined
    });
  });

  // AI Gemini trigger route for deep file evaluation
  router.post('/files/:id/analyze-ai', authenticateRequest, requireRole(['ORG_ADMIN', 'OPERATOR']), async (req: Request, res: Response) => {
    const { id } = req.params;
    const orgId = req.user!.orgId;
    const fileRow = db.prepare(`
      SELECT f.* FROM files f
      JOIN scans s ON f.scan_id = s.scan_id
      WHERE f.file_id = ? AND (s.org_id = ? OR s.org_id IS NULL)
    `).get(id, orgId) as any;
    if (!fileRow) return res.status(404).json({ error: 'File not found or unauthorized' });

    const findingsCount = db.prepare('SELECT COUNT(*) as count FROM findings WHERE file_id = ?').get(id) as { count: number };

    const aiResult = await analyzeContentWithGemini(
      fileRow.filename,
      fileRow.extension,
      fileRow.extracted_text_preview || '',
      findingsCount.count
    );

    if (aiResult) {
      db.prepare('UPDATE files SET ai_summary_json = ?, classification = ? WHERE file_id = ?')
        .run(JSON.stringify(aiResult), aiResult.classification, id);

      logAuditEvent('AI_ANALYSIS', fileRow.path, fileRow.sha256, 'SUCCESS', `AI Assigned classification: ${aiResult.classification}`);
      return res.json({ success: true, ai_summary: aiResult });
    }

    res.status(500).json({ error: 'AI evaluation unavailable or skipped due to missing API key.' });
  });

  // --- FINDINGS ---
  router.get('/findings', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    const rows = db.prepare(`
      SELECT f.*, fi.filename, fi.path as file_path
      FROM findings f
      JOIN files fi ON f.file_id = fi.file_id
      JOIN scans s ON fi.scan_id = s.scan_id
      WHERE s.org_id = ? OR s.org_id IS NULL
      ORDER BY 
        CASE f.severity
          WHEN 'CRITICAL' THEN 1
          WHEN 'HIGH' THEN 2
          WHEN 'MEDIUM' THEN 3
          WHEN 'LOW' THEN 4
          ELSE 5
        END, f.created_at DESC
      LIMIT 300
    `).all(orgId) as any[];

    const findings = rows.map(r => ({
      ...r,
      evidence: r.evidence_json ? JSON.parse(r.evidence_json) : {}
    }));

    res.json(findings);
  });

  // --- RULES ---
  router.get('/rules', (req: Request, res: Response) => {
    const rows = db.prepare('SELECT * FROM rules ORDER BY category, id').all() as any[];
    const rules = rows.map(r => ({
      id: r.id,
      name: r.name,
      category: r.category,
      severity: r.severity,
      enabled: Boolean(r.enabled),
      pattern: r.pattern,
      description: r.description,
      recommendation: r.recommendation,
      isBuiltIn: Boolean(r.is_builtin)
    }));
    res.json(rules);
  });

  router.post('/rules', authenticateRequest, requireRole(['ORG_ADMIN']), (req: Request, res: Response) => {
    const { id, name, category, severity, enabled, pattern, description, recommendation } = req.body;
    const newId = id || `RULE-${crypto.randomUUID().substring(0, 8)}`;

    const stmt = db.prepare(`
      INSERT INTO rules (id, name, category, severity, enabled, pattern, description, recommendation, is_builtin)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
    `);
    stmt.run(newId, name, category, severity, enabled ? 1 : 0, pattern, description, recommendation);

    logAuditEvent('CREATE_RULE', undefined, undefined, 'SUCCESS', `Created custom rule: ${newId}`);
    res.json({ success: true, id: newId });
  });

  router.put('/rules/:id/toggle', authenticateRequest, requireRole(['ORG_ADMIN']), (req: Request, res: Response) => {
    const { id } = req.params;
    const { enabled } = req.body;

    db.prepare('UPDATE rules SET enabled = ? WHERE id = ?').run(enabled ? 1 : 0, id);
    res.json({ success: true, id, enabled });
  });

  // --- QUARANTINE & VERIFIED CLOUD REMOVAL ---
  router.get('/quarantine', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    const rows = db.prepare(`
      SELECT q.* FROM quarantine_items q
      JOIN files f ON q.file_id = f.file_id
      JOIN scans s ON f.scan_id = s.scan_id
      WHERE s.org_id = ? OR s.org_id IS NULL
      ORDER BY q.quarantined_at DESC
    `).all(orgId) as any[];
    const items = rows.map(r => ({
      ...r,
      logs: r.logs_json ? JSON.parse(r.logs_json) : []
    }));
    res.json(items);
  });

  router.post('/quarantine/:file_id', authenticateRequest, requireRole(['ORG_ADMIN', 'OPERATOR']), (req: Request, res: Response) => {
    const { file_id } = req.params;
    const orgId = req.user!.orgId;
    const fileRow = db.prepare(`
      SELECT f.* FROM files f
      JOIN scans s ON f.scan_id = s.scan_id
      WHERE f.file_id = ? AND (s.org_id = ? OR s.org_id IS NULL)
    `).get(file_id, orgId) as any;
    if (!fileRow) return res.status(404).json({ error: 'File not found or unauthorized' });

    const qId = `Q-${crypto.randomUUID().substring(0, 8)}`;
    const logs = [`[${new Date().toISOString()}] File staged in quarantine registry`];

    const stmt = db.prepare(`
      INSERT INTO quarantine_items (
        id, file_id, original_path, filename, sha256, size, cloud_object,
        upload_status, verification_status, deletion_status, quarantined_at, logs_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', 'PENDING', 'NOT_DELETED', ?, ?)
    `);

    stmt.run(
      qId,
      file_id,
      fileRow.path,
      fileRow.filename,
      fileRow.sha256,
      fileRow.size,
      `${fileRow.sha256}_${fileRow.filename}`,
      new Date().toISOString(),
      JSON.stringify(logs)
    );

    logAuditEvent('QUARANTINE_STAGE', fileRow.path, fileRow.sha256, 'SUCCESS', `Quarantine Item: ${qId}`);

    res.json({ success: true, quarantine_id: qId });
  });

  // CRITICAL CORRECTION: Local file deletion route disabled and removed completely (Phase 6A: local files must never be deleted).
  router.post('/quarantine/:file_id/upload-and-remove', authenticateRequest, requireRole(['ORG_ADMIN', 'OPERATOR']), (req: Request, res: Response) => {
    return res.status(404).json({ error: 'Endpoint disabled or not supported. Local files are never deleted.' });
  });

  // --- DASHBOARD STATS ---
  router.get('/dashboard/stats', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    const totalScans = (db.prepare('SELECT COUNT(*) as c FROM scans WHERE org_id = ? OR org_id IS NULL').get(orgId) as any).c;
    const totalFilesScanned = (db.prepare(`
      SELECT COUNT(*) as c FROM files f JOIN scans s ON f.scan_id = s.scan_id WHERE s.org_id = ? OR s.org_id IS NULL
    `).get(orgId) as any).c;

    const critical = (db.prepare(`
      SELECT COUNT(*) as c FROM files f JOIN scans s ON f.scan_id = s.scan_id WHERE (s.org_id = ? OR s.org_id IS NULL) AND f.risk_score >= 80
    `).get(orgId) as any).c;
    const high = (db.prepare(`
      SELECT COUNT(*) as c FROM files f JOIN scans s ON f.scan_id = s.scan_id WHERE (s.org_id = ? OR s.org_id IS NULL) AND f.risk_score >= 50 AND f.risk_score < 80
    `).get(orgId) as any).c;
    const medium = (db.prepare(`
      SELECT COUNT(*) as c FROM files f JOIN scans s ON f.scan_id = s.scan_id WHERE (s.org_id = ? OR s.org_id IS NULL) AND f.risk_score >= 20 AND f.risk_score < 50
    `).get(orgId) as any).c;
    const low = (db.prepare(`
      SELECT COUNT(*) as c FROM files f JOIN scans s ON f.scan_id = s.scan_id WHERE (s.org_id = ? OR s.org_id IS NULL) AND f.risk_score > 0 AND f.risk_score < 20
    `).get(orgId) as any).c;
    const safe = (db.prepare(`
      SELECT COUNT(*) as c FROM files f JOIN scans s ON f.scan_id = s.scan_id WHERE (s.org_id = ? OR s.org_id IS NULL) AND f.risk_score = 0
    `).get(orgId) as any).c;

    const recentScans = db.prepare('SELECT * FROM scans WHERE org_id = ? OR org_id IS NULL ORDER BY start_time DESC LIMIT 5').all(orgId);
    const highestRiskFiles = db.prepare(`
      SELECT f.* FROM files f JOIN scans s ON f.scan_id = s.scan_id WHERE s.org_id = ? OR s.org_id IS NULL ORDER BY f.risk_score DESC LIMIT 5
    `).all(orgId);
    const recentFindings = db.prepare(`
      SELECT f.*, fi.filename FROM findings f
      JOIN files fi ON f.file_id = fi.file_id
      JOIN scans s ON fi.scan_id = s.scan_id
      WHERE s.org_id = ? OR s.org_id IS NULL
      ORDER BY f.created_at DESC LIMIT 6
    `).all(orgId);
    const quarantinedCount = (db.prepare(`
      SELECT COUNT(*) as c FROM quarantine_items q
      JOIN files fi ON q.file_id = fi.file_id
      JOIN scans s ON fi.scan_id = s.scan_id
      WHERE s.org_id = ? OR s.org_id IS NULL
    `).get(orgId) as any).c;

    res.json({
      totalScans,
      totalFilesScanned,
      riskBreakdown: { critical, high, medium, low, safe },
      quarantinedCount,
      recentScans,
      highestRiskFiles,
      recentFindings
    });
  });

  // AUDIT LOGS
  router.get('/audit-logs', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR']), (req: Request, res: Response) => {
    const orgId = req.user!.orgId;
    const rows = db.prepare('SELECT * FROM security_audit_events WHERE org_id = ? OR org_id IS NULL ORDER BY timestamp DESC LIMIT 100').all(orgId);
    res.json(rows);
  });

  // --- AUDIT COMPLIANCE ENDPOINTS ---
  const evidenceEngine = new EvidenceEngine(db);

  // Trigger Audit Compliance Scan
  router.post('/audit/run', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR']), async (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const featCheck = licensingEngine.validateLicense(orgId, {
        deviceId: req.user!.deviceId,
        requiredFeature: 'AUDIT_ENGINE',
        actorId: req.user!.userId
      });
      if (!featCheck.valid) {
        return res.status(403).json({
          error: featCheck.error || 'Audit engine requires an upgraded license plan',
          ui_state: featCheck.ui_state,
          status: featCheck.status
        });
      }

      const { target_dir, scan_roots, scan_id, audit_date, agency_name, auditor_name } = req.body;
      
      let session;
      
      if (scan_id) {
        session = await evidenceEngine.runAuditScanForSession(
          scan_id,
          audit_date || new Date().toISOString().split('T')[0],
          agency_name || 'Primary Telecalling & Collection Agency',
          auditor_name || 'Automated Compliance Inspector'
        );
        logAuditEvent('RUN_AUDIT_COMPLIANCE', scan_id, undefined, 'SUCCESS', `Audit ID: ${session.audit_id}, Score: ${session.overall_score}`);
      } else {
        const roots = scan_roots || (target_dir ? [target_dir] : []);
        if (!roots || roots.length === 0 || roots.every((r: string) => !r.trim())) {
          return res.status(400).json({ error: 'Please specify at least one target directory path or scan ID for audit evaluation.' });
        }
        const validRoots = roots.map((r: string) => path.resolve(r.trim())).filter((r: string) => fs.existsSync(r));

        if (validRoots.length === 0) {
          return res.status(400).json({ error: `None of the provided directory targets exist.` });
        }

        // Collect file paths
        const filePaths: string[] = [];
        function collectFiles(dir: string) {
          const entries = fs.readdirSync(dir, { withFileTypes: true });
          for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) collectFiles(fullPath);
            else filePaths.push(fullPath);
          }
        }
        for (const root of validRoots) {
          collectFiles(root);
        }

        session = await evidenceEngine.runAuditScan(
          filePaths,
          audit_date || new Date().toISOString().split('T')[0],
          agency_name || 'Primary Telecalling & Collection Agency',
          auditor_name || 'Automated Compliance Inspector',
          undefined,
          currentSettings.aiPrivacyMode || 'OFF'
        );

        logAuditEvent('RUN_AUDIT_COMPLIANCE', validRoots.join(', '), undefined, 'SUCCESS', `Audit ID: ${session.audit_id}, Score: ${session.overall_score}`);
      }
      
      res.json(session);
    } catch (err: any) {
      console.error('[API] Audit run error:', err);
      res.status(500).json({ error: err.message || 'Audit execution failed' });
    }
  });

  // List past audit sessions
  router.get('/audit/sessions', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const rows = db.prepare(`
        SELECT a.* FROM audit_sessions a
        LEFT JOIN scans s ON a.scan_id = s.scan_id
        WHERE s.org_id = ? OR s.org_id IS NULL OR a.scan_id IS NULL
        ORDER BY a.created_at DESC LIMIT 50
      `).all(orgId) as any[];
      const sessions = rows.map(r => ({
        ...r,
        category_scores: r.category_scores_json ? JSON.parse(r.category_scores_json) : {}
      }));
      res.json(sessions);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Get specific audit session details with parameters and evidence
  router.get('/audit/session/:id', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const sessionRow = db.prepare('SELECT * FROM audit_sessions WHERE audit_id = ?').get(req.params.id) as any;
      if (!sessionRow) {
        return res.status(404).json({ error: 'Audit session not found' });
      }
      if (sessionRow.scan_id) {
        const scanRow = db.prepare('SELECT org_id FROM scans WHERE scan_id = ?').get(sessionRow.scan_id) as any;
        if (scanRow && scanRow.org_id && scanRow.org_id !== orgId) {
          return res.status(403).json({ error: 'Access denied: Cross-tenant audit session access forbidden' });
        }
      }

      const paramRows = db.prepare('SELECT * FROM audit_parameter_results WHERE audit_id = ?').all(req.params.id) as any[];

      const activeChecklistMap = new Map(INITIAL_AUDIT_CHECKLIST.map(p => [p.id, p]));

      const parameterResults = paramRows.map(pr => {
        const checklistParam = activeChecklistMap.get(pr.parameter_id) || {
          id: pr.parameter_id,
          category: 'ZERO_TOLERANCE',
          category_name: 'Audit Parameter',
          category_weight: 100,
          parameter: pr.parameter_id,
          fatal: Boolean(pr.fatal),
          severity: 'HIGH',
          required_evidence: [],
          keywords: [],
          logic: 'SINGLE',
          evaluation_rules: [],
          enabled: true
        };

        return {
          parameter_id: pr.parameter_id,
          parameter: checklistParam,
          status: pr.status,
          confidence: pr.confidence,
          fatal: Boolean(pr.fatal),
          score_earned: pr.score_earned,
          max_score: pr.max_score,
          policy_status: pr.policy_status,
          pv_status: pr.pv_status,
          evidence: pr.evidence_json ? (JSON.parse(pr.evidence_json).evidence || JSON.parse(pr.evidence_json)) : [],
          evidence_set: pr.evidence_json && JSON.parse(pr.evidence_json).evidence_set ? JSON.parse(pr.evidence_json).evidence_set : undefined,
          reason: pr.reason,
          missing_requirements: pr.missing_requirements_json ? JSON.parse(pr.missing_requirements_json) : [],
          warnings: pr.warnings_json ? JSON.parse(pr.warnings_json) : [],
          ai_recommendation: pr.ai_recommendation_json ? JSON.parse(pr.ai_recommendation_json) : undefined,
          override: pr.override_json ? JSON.parse(pr.override_json) : undefined
        };
      });

      // Load entities and conflicts
      let entities: any[] = [];
      let entityConflicts: any[] = [];
      try {
        const entityRows = db.prepare('SELECT * FROM audit_entities WHERE audit_id = ?').all(req.params.id) as any[];
        entities = entityRows.map(e => ({
          ...e,
          identifiers: e.identifiers_json ? JSON.parse(e.identifiers_json) : {},
          evidenceReferences: e.evidence_references_json ? JSON.parse(e.evidence_references_json) : [],
          matchingSignals: e.matching_signals_json ? JSON.parse(e.matching_signals_json) : [],
          conflicts: e.conflicts_json ? JSON.parse(e.conflicts_json) : []
        }));

        const conflictRows = db.prepare('SELECT * FROM audit_entity_conflicts WHERE audit_id = ?').all(req.params.id) as any[];
        entityConflicts = conflictRows.map(c => ({
          ...c,
          involvedEvidence: c.involved_evidence_json ? JSON.parse(c.involved_evidence_json) : [],
          conflictingAttributes: c.conflicting_attributes_json ? JSON.parse(c.conflicting_attributes_json) : {}
        }));
      } catch (e) {
        // Fallback gracefully if table not yet queried
      }

      const session = {
        ...sessionRow,
        category_scores: sessionRow.category_scores_json ? JSON.parse(sessionRow.category_scores_json) : {},
        parameter_results: parameterResults,
        entities,
        entity_conflicts: entityConflicts,
        entityConflicts
      };

      res.json(session);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Auditor Override Endpoint
  router.post('/audit/override', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR']), (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const { audit_id, parameter_id, new_status, auditor_name, comment } = req.body;

      if (!audit_id || !parameter_id || !new_status || !auditor_name) {
        return res.status(400).json({ error: 'Missing required override fields' });
      }

      const sessionRow = db.prepare('SELECT * FROM audit_sessions WHERE audit_id = ?').get(audit_id) as any;
      if (!sessionRow) {
        return res.status(404).json({ error: 'Audit session not found' });
      }
      if (sessionRow.scan_id) {
        const scanRow = db.prepare('SELECT org_id FROM scans WHERE scan_id = ?').get(sessionRow.scan_id) as any;
        if (scanRow && scanRow.org_id && scanRow.org_id !== orgId) {
          return res.status(403).json({ error: 'Access denied: Cross-tenant audit override forbidden' });
        }
      }

      // Fetch existing result
      const row = db.prepare('SELECT * FROM audit_parameter_results WHERE audit_id = ? AND parameter_id = ?').get(audit_id, parameter_id) as any;
      if (!row) {
        return res.status(404).json({ error: 'Audit parameter result not found' });
      }

      const override = {
        original_status: row.status,
        new_status,
        auditor_name,
        comment: comment || 'Manual auditor override applied',
        timestamp: new Date().toISOString()
      };

      // Update parameter result in DB
      db.prepare(`
        UPDATE audit_parameter_results
        SET override_json = ?
        WHERE audit_id = ? AND parameter_id = ?
      `).run(JSON.stringify(override), audit_id, parameter_id);

      // Recalculate Audit Session Scores
      const updatedSessionRow = db.prepare('SELECT * FROM audit_sessions WHERE audit_id = ?').get(audit_id) as any;
      const allParamRows = db.prepare('SELECT * FROM audit_parameter_results WHERE audit_id = ?').all(audit_id) as any[];

      const checklistMap = new Map(INITIAL_AUDIT_CHECKLIST.map(p => [p.id, p]));

      const fullResults = allParamRows.map(pr => ({
        parameter_id: pr.parameter_id,
        parameter: checklistMap.get(pr.parameter_id) || INITIAL_AUDIT_CHECKLIST[0],
        status: pr.status,
        confidence: pr.confidence,
        fatal: Boolean(pr.fatal),
        score_earned: pr.score_earned,
        max_score: pr.max_score,
        policy_status: pr.policy_status,
        pv_status: pr.pv_status,
        evidence: pr.evidence_json ? (JSON.parse(pr.evidence_json).evidence || JSON.parse(pr.evidence_json)) : [],
          evidence_set: pr.evidence_json && JSON.parse(pr.evidence_json).evidence_set ? JSON.parse(pr.evidence_json).evidence_set : undefined,
        reason: pr.reason,
        missing_requirements: pr.missing_requirements_json ? JSON.parse(pr.missing_requirements_json) : [],
        warnings: pr.warnings_json ? JSON.parse(pr.warnings_json) : [],
        override: pr.override_json ? JSON.parse(pr.override_json) : undefined
      }));

      const updatedSession = AuditScoringEngine.calculateAuditSummary(
        audit_id,
        updatedSessionRow.agency_name,
        updatedSessionRow.auditor_name,
        updatedSessionRow.audit_date,
        fullResults as any
      );

      // Save updated totals to session
      db.prepare(`
        UPDATE audit_sessions
        SET pass_count = ?, fail_count = ?, review_count = ?, not_found_count = ?,
            fatal_failures_count = ?, overall_score = ?, overall_status = ?,
            category_scores_json = ?, updated_at = ?
        WHERE audit_id = ?
      `).run(
        updatedSession.pass_count,
        updatedSession.fail_count,
        updatedSession.review_count,
        updatedSession.not_found_count,
        updatedSession.fatal_failures_count,
        updatedSession.overall_score,
        updatedSession.overall_status,
        JSON.stringify(updatedSession.category_scores),
        new Date().toISOString(),
        audit_id
      );

      logAuditEvent('AUDITOR_OVERRIDE', audit_id, undefined, 'SUCCESS', `Parameter ${parameter_id} overridden to ${new_status} by ${auditor_name}`);

      res.json({ success: true, override, session: updatedSession });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Get Active Checklist Parameters
  router.get('/audit/checklist', (req: Request, res: Response) => {
    res.json(INITIAL_AUDIT_CHECKLIST);
  });

  // Get Evidence Gaps
  router.get('/audit/gaps/:id', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const sessionRow = db.prepare('SELECT * FROM audit_sessions WHERE audit_id = ?').get(req.params.id) as any;
      if (!sessionRow) {
        return res.status(404).json({ error: 'Audit session not found' });
      }

      // Check tenant isolation if scan is associated with an org
      if (sessionRow.scan_id) {
        const scanRow = db.prepare('SELECT org_id FROM scans WHERE scan_id = ?').get(sessionRow.scan_id) as any;
        if (scanRow && scanRow.org_id && scanRow.org_id !== orgId) {
          return res.status(403).json({ error: 'Access denied: Cross-tenant audit access forbidden' });
        }
      }

      const paramRows = db.prepare('SELECT * FROM audit_parameter_results WHERE audit_id = ?').all(req.params.id) as any[];
      const activeChecklistMap = new Map(INITIAL_AUDIT_CHECKLIST.map(p => [p.id, p]));

      const parameterResults = paramRows.map(pr => ({
        parameter_id: pr.parameter_id,
        parameter: activeChecklistMap.get(pr.parameter_id) || INITIAL_AUDIT_CHECKLIST[0],
        status: pr.status,
        confidence: pr.confidence,
        fatal: Boolean(pr.fatal),
        score_earned: pr.score_earned,
        max_score: pr.max_score,
        evidence: pr.evidence_json ? (JSON.parse(pr.evidence_json).evidence || JSON.parse(pr.evidence_json)) : [],
        evidence_set: pr.evidence_json && JSON.parse(pr.evidence_json).evidence_set ? JSON.parse(pr.evidence_json).evidence_set : undefined,
        reason: pr.reason,
        missing_requirements: pr.missing_requirements_json ? JSON.parse(pr.missing_requirements_json) : [],
        warnings: pr.warnings_json ? JSON.parse(pr.warnings_json) : [],
        override: pr.override_json ? JSON.parse(pr.override_json) : undefined
      }));

      const session = {
        ...sessionRow,
        category_scores: sessionRow.category_scores_json ? JSON.parse(sessionRow.category_scores_json) : {},
        parameter_results: parameterResults
      };

      const gaps = evidenceEngine.generateEvidenceGaps(session as any);
      res.json(gaps);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Export Audit Report
  router.get('/audit/report/:id/:format', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const sessionRow = db.prepare('SELECT * FROM audit_sessions WHERE audit_id = ?').get(req.params.id) as any;
      if (!sessionRow) {
        return res.status(404).json({ error: 'Audit session not found' });
      }

      if (sessionRow.scan_id) {
        const scanRow = db.prepare('SELECT org_id FROM scans WHERE scan_id = ?').get(sessionRow.scan_id) as any;
        if (scanRow && scanRow.org_id && scanRow.org_id !== orgId) {
          return res.status(403).json({ error: 'Access denied: Cross-tenant audit report export forbidden' });
        }
      }

      const paramRows = db.prepare('SELECT * FROM audit_parameter_results WHERE audit_id = ?').all(req.params.id) as any[];
      const activeChecklistMap = new Map(INITIAL_AUDIT_CHECKLIST.map(p => [p.id, p]));

      const parameterResults = paramRows.map(pr => ({
        parameter_id: pr.parameter_id,
        parameter: activeChecklistMap.get(pr.parameter_id) || INITIAL_AUDIT_CHECKLIST[0],
        status: pr.status,
        confidence: pr.confidence,
        fatal: Boolean(pr.fatal),
        score_earned: pr.score_earned,
        max_score: pr.max_score,
        policy_status: pr.policy_status,
        pv_status: pr.pv_status,
        evidence: pr.evidence_json ? (JSON.parse(pr.evidence_json).evidence || JSON.parse(pr.evidence_json)) : [],
        evidence_set: pr.evidence_json && JSON.parse(pr.evidence_json).evidence_set ? JSON.parse(pr.evidence_json).evidence_set : undefined,
        reason: pr.reason,
        missing_requirements: pr.missing_requirements_json ? JSON.parse(pr.missing_requirements_json) : [],
        warnings: pr.warnings_json ? JSON.parse(pr.warnings_json) : [],
        override: pr.override_json ? JSON.parse(pr.override_json) : undefined
      }));

      const session = {
        ...sessionRow,
        category_scores: sessionRow.category_scores_json ? JSON.parse(sessionRow.category_scores_json) : {},
        parameter_results: parameterResults
      };

      // Automatically register / sync verifiable audit report record
      const registered = verifiableReportService.registerReport({
        scan_id: session.scan_id || `FS-SCAN-${session.audit_id}`,
        organization_id: orgId,
        session: session as any
      });

      const reportMeta = {
        report_id: registered.report_id,
        scan_id: registered.scan_id,
        organization_id: registered.organization_id,
        engine_version: registered.engine_version,
        checklist_version: registered.checklist_version,
        generated_at: registered.generated_at,
        report_hash: registered.report_hash
      };

      const format = req.params.format.toLowerCase();
      if (format === 'json') {
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="AuditReport_${registered.report_id}.json"`);
        return res.send(AuditReportGenerator.generateJson(session as any, reportMeta));
      } else if (format === 'csv') {
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="AuditReport_${registered.report_id}.csv"`);
        return res.send(AuditReportGenerator.generateCsv(session as any, reportMeta));
      } else {
        res.setHeader('Content-Type', 'text/html');
        return res.send(AuditReportGenerator.generateHtml(session as any, reportMeta));
      }
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // --- COMMERCIALIZATION PHASE 9: CRYPTOGRAPHICALLY VERIFIABLE AUDIT REPORTS ---

  // POST /api/reports/register (Authentic report registration)
  router.post('/reports/register', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR']), async (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const { scan_id, audit_id, engine_version, checklist_version, canonical_report, report_hash, custom_report_hash } = req.body;

      if (!scan_id && !audit_id && !canonical_report?.scan_id) {
        return res.status(400).json({ error: 'scan_id or audit_id is required to register an audit report' });
      }

      let session: any = undefined;
      const targetAuditId = audit_id || (scan_id && db.prepare('SELECT audit_id FROM audit_sessions WHERE scan_id = ?').get(scan_id) as any)?.audit_id;
      
      if (targetAuditId) {
        const sessionRow = db.prepare('SELECT * FROM audit_sessions WHERE audit_id = ?').get(targetAuditId) as any;
        if (sessionRow) {
          const paramRows = db.prepare('SELECT * FROM audit_parameter_results WHERE audit_id = ?').all(targetAuditId) as any[];
          const activeChecklistMap = new Map(INITIAL_AUDIT_CHECKLIST.map(p => [p.id, p]));
          session = {
            ...sessionRow,
            category_scores: sessionRow.category_scores_json ? JSON.parse(sessionRow.category_scores_json) : {},
            parameter_results: paramRows.map(pr => ({
              parameter_id: pr.parameter_id,
              parameter: activeChecklistMap.get(pr.parameter_id) || INITIAL_AUDIT_CHECKLIST[0],
              status: pr.status,
              confidence: pr.confidence,
              fatal: Boolean(pr.fatal),
              score_earned: pr.score_earned,
              max_score: pr.max_score,
              evidence: pr.evidence_json ? (JSON.parse(pr.evidence_json).evidence || JSON.parse(pr.evidence_json)) : [],
              reason: pr.reason,
              override: pr.override_json ? JSON.parse(pr.override_json) : undefined
            }))
          };
        }
      }

      const result = verifiableReportService.registerReport({
        scan_id: scan_id || session?.scan_id || `FS-SCAN-${targetAuditId || 'GENERAL'}`,
        organization_id: orgId,
        engine_version,
        checklist_version,
        canonical_report,
        session,
        custom_report_hash: custom_report_hash || report_hash
      });

      logAuditEvent('REPORT_REGISTERED', result.report_id, undefined, 'SUCCESS', `Verifiable Report registered: ${result.report_id} (${result.report_hash.substring(0, 12)}...)`);

      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/reports/verify/:report_id (Public / Read-only verification endpoint)
  router.get('/reports/verify/:report_id', (req: Request, res: Response) => {
    try {
      const { report_id } = req.params;
      const result = verifiableReportService.verifyReport(report_id);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/reports/verify (Alternative POST verification for convenience)
  router.post('/reports/verify', (req: Request, res: Response) => {
    try {
      const { report_id, query_id } = req.body;
      const idToVerify = report_id || query_id;
      if (!idToVerify) {
        return res.status(400).json({ status: 'INVALID', message: 'Missing report_id to verify' });
      }
      const result = verifiableReportService.verifyReport(idToVerify);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/reports/list (Organization reports list)
  router.get('/reports/list', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const reports = verifiableReportService.listReports(orgId);
      res.json(reports);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/reports/:report_id/download', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const userId = req.user!.userId;
      const deviceId = req.user!.deviceId;
      const reportId = req.params.report_id;
      const report = verifiableReportService.getReport(reportId);
      if (!report || report.organization_id !== orgId) {
        return res.status(404).json({ error: 'Report not found' });
      }
      try {
        const pilotService = new PilotService(db);
        pilotService.recordTelemetry('report_export', orgId, userId, deviceId, { report_id: reportId });
      } catch {}
      res.json(report);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/reports/revoke/:report_id (Revoke an audit report)
  router.post('/reports/revoke/:report_id', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR']), (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const { report_id } = req.params;
      const { reason } = req.body;

      const result = verifiableReportService.revokeReport(report_id, reason || 'Administrative revocation', orgId);
      if (!result.success) {
        return res.status(400).json({ error: result.message });
      }

      logAuditEvent('REPORT_REVOKED', report_id, undefined, 'SUCCESS', `Audit report revoked: ${report_id}`);

      res.json({ success: true, report_id, status: 'REVOKED' });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // --- PHASE 6A: CLOUD UPLOAD ONLY / NON-DESTRUCTIVE QUARANTINE ---
  router.get('/cloud-uploads', authenticateRequest, requireRole(['ORG_ADMIN', 'AUDITOR', 'OPERATOR', 'VIEWER']), (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const rows = db.prepare(`
        SELECT u.* FROM file_cloud_uploads u
        JOIN files f ON u.file_id = f.file_id
        JOIN scans s ON f.scan_id = s.scan_id
        WHERE s.org_id = ? OR s.org_id IS NULL
      `).all(orgId);
      res.json(rows);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  async function processFileUpload(fileId: string): Promise<any> {
    const fileRow = db.prepare('SELECT * FROM files WHERE file_id = ?').get(fileId) as any;
    if (!fileRow) {
      return { file_id: fileId, success: false, status: 'UPLOAD_FAILED', error: 'File not found' };
    }

    const localPath = fileRow.path;
    const sha256 = fileRow.sha256;
    const bucketName = process.env.GOOGLE_CLOUD_BUCKET || 'filesentinel-quarantine-bucket';
    const sanitizedFilename = path.basename(localPath).replace(/[^a-zA-Z0-9_.-]/g, '_');
    const cloudObjectName = `filesentinel/${fileRow.scan_id || 'general'}/${fileId}/${sanitizedFilename}`;

    const existingUpload = db.prepare('SELECT * FROM file_cloud_uploads WHERE file_id = ?').get(fileId) as any;
    if (existingUpload && existingUpload.upload_status === 'UPLOADED') {
      const verified = await cloudStorage.verify(cloudObjectName, sha256, fileRow.size);
      if (verified) {
        return {
          file_id: fileId,
          filename: fileRow.filename,
          success: true,
          status: 'ALREADY_UPLOADED',
          cloud_object_name: cloudObjectName,
          sha256,
          local_file_retained: fs.existsSync(localPath)
        };
      }
    }

    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO file_cloud_uploads (file_id, scan_id, audit_session_id, original_filename, local_path, sha256, size, cloud_bucket, cloud_object_name, upload_status, uploaded_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'UPLOADING', ?)
      ON CONFLICT(file_id) DO UPDATE SET upload_status = 'UPLOADING', uploaded_at = ?
    `).run(fileId, fileRow.scan_id, null, fileRow.filename, localPath, sha256, fileRow.size, bucketName, cloudObjectName, now, now);

    logAuditEvent('UPLOAD_STARTED', localPath, sha256, 'SUCCESS', `Started upload for ${fileRow.filename}`);

    if (!fs.existsSync(localPath)) {
      const errMsg = 'Local file missing before upload';
      db.prepare(`UPDATE file_cloud_uploads SET upload_status = 'UPLOAD_FAILED', error_message = ? WHERE file_id = ?`).run(errMsg, fileId);
      logAuditEvent('UPLOAD_FAILED', localPath, sha256, 'ERROR', errMsg);
      return { file_id: fileId, success: false, status: 'UPLOAD_FAILED', error: errMsg };
    }

    const currentHash = scannerEngine.calculateSHA256(localPath);
    if (currentHash !== sha256) {
      const errMsg = 'SHA-256 checksum mismatch';
      db.prepare(`UPDATE file_cloud_uploads SET upload_status = 'UPLOAD_FAILED', error_message = ? WHERE file_id = ?`).run(errMsg, fileId);
      logAuditEvent('UPLOAD_FAILED', localPath, sha256, 'ERROR', errMsg);
      return { file_id: fileId, success: false, status: 'UPLOAD_FAILED', error: errMsg };
    }

    const uploadSuccess = await cloudStorage.upload(localPath, cloudObjectName);
    if (!uploadSuccess) {
      const errMsg = 'Cloud storage upload failed';
      db.prepare(`UPDATE file_cloud_uploads SET upload_status = 'UPLOAD_FAILED', error_message = ? WHERE file_id = ?`).run(errMsg, fileId);
      logAuditEvent('UPLOAD_FAILED', localPath, sha256, 'ERROR', errMsg);
      return { file_id: fileId, success: false, status: 'UPLOAD_FAILED', error: errMsg, local_file_retained: fs.existsSync(localPath) };
    }

    logAuditEvent('UPLOAD_SUCCESS', localPath, sha256, 'SUCCESS', `Uploaded to ${cloudObjectName}`);

    const verified = await cloudStorage.verify(cloudObjectName, sha256, fileRow.size);
    if (!verified) {
      const errMsg = 'Cloud verification failed or hash mismatch';
      db.prepare(`UPDATE file_cloud_uploads SET upload_status = 'VERIFICATION_FAILED', error_message = ? WHERE file_id = ?`).run(errMsg, fileId);
      logAuditEvent('UPLOAD_VERIFICATION_FAILED', localPath, sha256, 'ERROR', errMsg);
      return { file_id: fileId, success: false, status: 'VERIFICATION_FAILED', error: errMsg, local_file_retained: fs.existsSync(localPath) };
    }

    const verifiedAt = new Date().toISOString();
    db.prepare(`
      UPDATE file_cloud_uploads
      SET upload_status = 'UPLOADED', verified_at = ?, error_message = NULL
      WHERE file_id = ?
    `).run(verifiedAt, fileId);

    logAuditEvent('UPLOAD_VERIFICATION_SUCCESS', localPath, sha256, 'SUCCESS', `Verified remote object ${cloudObjectName}`);

    const localFileExists = fs.existsSync(localPath);

    return {
      file_id: fileId,
      filename: fileRow.filename,
      success: true,
      status: 'UPLOADED',
      cloud_object_name: cloudObjectName,
      sha256,
      local_file_retained: localFileExists
    };
  }

  router.post('/cloud-uploads/upload', authenticateRequest, requireRole(['ORG_ADMIN', 'OPERATOR']), async (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const featCheck = licensingEngine.validateLicense(orgId, {
        deviceId: req.user!.deviceId,
        requiredFeature: 'CLOUD_EVIDENCE_UPLOAD',
        actorId: req.user!.userId
      });
      if (!featCheck.valid) {
        return res.status(403).json({
          error: featCheck.error || 'Cloud evidence upload requires an upgraded license plan',
          ui_state: featCheck.ui_state,
          status: featCheck.status
        });
      }

      const { file_ids } = req.body;
      if (!Array.isArray(file_ids) || file_ids.length === 0) {
        return res.status(400).json({ error: 'file_ids array is required' });
      }

      if (file_ids.length > 500) {
        return res.status(400).json({ error: 'Batch size exceeds maximum allowed limit (500 files).' });
      }

      for (const fileId of file_ids) {
        if (!isValidFileId(fileId)) {
          return res.status(400).json({ error: `Invalid file ID format or security violation: ${fileId}` });
        }
        const fileRow = db.prepare(`
          SELECT f.* FROM files f JOIN scans s ON f.scan_id = s.scan_id
          WHERE f.file_id = ? AND (s.org_id = ? OR s.org_id IS NULL)
        `).get(fileId, orgId);
        if (!fileRow) {
          return res.status(403).json({ error: `Access denied: File not found or unauthorized: ${fileId}` });
        }
      }

      const results: any[] = [];
      for (const fileId of file_ids) {
        const resItem = await processFileUpload(fileId);
        results.push(resItem);
      }

      const successCount = results.filter(r => r.success || r.status === 'ALREADY_UPLOADED').length;
      const failedCount = results.length - successCount;

      res.json({
        success: failedCount === 0,
        total_selected: results.length,
        success_count: successCount,
        failed_count: failedCount,
        results
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/cloud-uploads/upload-all', authenticateRequest, requireRole(['ORG_ADMIN', 'OPERATOR']), async (req: Request, res: Response) => {
    try {
      const orgId = req.user!.orgId;
      const featCheck = licensingEngine.validateLicense(orgId, {
        deviceId: req.user!.deviceId,
        requiredFeature: 'CLOUD_EVIDENCE_UPLOAD',
        actorId: req.user!.userId
      });
      if (!featCheck.valid) {
        return res.status(403).json({
          error: featCheck.error || 'Cloud evidence upload requires an upgraded license plan',
          ui_state: featCheck.ui_state,
          status: featCheck.status
        });
      }

      const { scan_id } = req.body;
      let query = 'SELECT f.file_id FROM files f JOIN scans s ON f.scan_id = s.scan_id WHERE (s.org_id = ? OR s.org_id IS NULL)';
      const params: any[] = [orgId];
      if (scan_id) {
        if (typeof scan_id !== 'string' || scan_id.length > 64) {
          return res.status(400).json({ error: 'Invalid scan_id parameter' });
        }
        const scanRow = db.prepare('SELECT org_id FROM scans WHERE scan_id = ?').get(scan_id) as any;
        if (scanRow && scanRow.org_id && scanRow.org_id !== orgId) {
          return res.status(403).json({ error: 'Access denied: Cross-tenant scan upload forbidden' });
        }
        query += ' AND f.scan_id = ?';
        params.push(scan_id);
      }
      const fileRows = db.prepare(query).all(...params) as any[];
      const fileIds = fileRows.map(r => r.file_id);

      if (fileIds.length > 5000) {
        return res.status(400).json({ error: 'Upload-all batch limit exceeded (max 5000 files).' });
      }

      const results: any[] = [];
      for (const fileId of fileIds) {
        const resItem = await processFileUpload(fileId);
        results.push(resItem);
      }

      const successCount = results.filter(r => r.success || r.status === 'ALREADY_UPLOADED').length;
      const failedCount = results.length - successCount;

      res.json({
        success: failedCount === 0,
        total_scanned: results.length,
        success_count: successCount,
        failed_count: failedCount,
        results
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/cloud-uploads/retry/:file_id', async (req: Request, res: Response) => {
    try {
      const { file_id } = req.params;
      if (!isValidFileId(file_id)) {
        return res.status(400).json({ error: 'Invalid file ID format or security violation.' });
      }
      const result = await processFileUpload(file_id);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  router.use('/admin', createAdminRouter(db));

  return router;
}
