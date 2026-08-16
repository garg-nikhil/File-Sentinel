import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import { hashPassword } from './auth.js';

export class PilotService {
  private db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
  }

  public isPilotModeEnabled(): boolean {
    return process.env.PILOT_MODE !== 'false';
  }

  public recordTelemetry(eventType: string, orgId: string, userId?: string, deviceId?: string, details?: any): void {
    const eventId = 'pte-' + crypto.randomBytes(12).toString('hex');
    const now = new Date().toISOString();
    try {
      this.db.prepare(`
        INSERT INTO pilot_telemetry_events (event_id, event_type, org_id, user_id, device_id, details_json, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        eventId,
        eventType,
        orgId,
        userId || null,
        deviceId || null,
        details ? JSON.stringify(details) : null,
        now
      );
    } catch (err) {
      console.error('[PilotService] Failed to record telemetry:', err);
    }
  }

  public createPilotOrganization(params: {
    org_name: string;
    admin_username: string;
    admin_password?: string;
    duration_days?: number;
    admin_user_id: string;
  }) {
    const orgId = 'org-pilot-' + crypto.randomBytes(6).toString('hex');
    const userId = 'user-pilot-' + crypto.randomBytes(6).toString('hex');
    const deviceId = 'dev-pilot-' + crypto.randomBytes(6).toString('hex');
    const licenseId = 'lic-pilot-' + crypto.randomBytes(6).toString('hex');
    const now = new Date().toISOString();
    const durationDays = params.duration_days || 14;
    const trialEnd = new Date(Date.now() + durationDays * 24 * 3600 * 1000).toISOString();
    const graceUntil = new Date(Date.now() + (durationDays + 7) * 24 * 3600 * 1000).toISOString();

    const password = params.admin_password || 'Pilot123!';
    const passwordHash = hashPassword(password);

    // 1. Create Organization
    this.db.prepare('INSERT INTO organizations (org_id, name, suspended, created_at) VALUES (?, ?, 0, ?)').run(
      orgId, params.org_name, now
    );

    // 2. Create Admin User
    this.db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)').run(
      userId, orgId, params.admin_username, passwordHash, 'ORG_ADMIN', now
    );

    // 3. Create Default Device
    this.db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 0, ?)').run(
      deviceId, orgId, 'Pilot Primary Device', now
    );

    // 4. Issue TRIAL License
    const features = JSON.stringify(['LOCAL_SCANNING', 'AUDIT_ENGINE', 'CENTRAL_HISTORY']);
    this.db.prepare(`
      INSERT INTO licenses (
        license_id, organization_id, plan_id, status, issued_at, starts_at, expires_at,
        grace_until, max_users, max_devices, scan_limit, scans_used, feature_flags,
        trial_start, trial_end, trial_status, created_at, updated_at, last_validated_at
      ) VALUES (?, ?, 'plan-starter-trial', 'TRIAL', ?, ?, ?, ?, 3, 3, 25, 0, ?, ?, ?, 'ACTIVE', ?, ?, ?)
    `).run(
      licenseId,
      orgId,
      now,
      now,
      trialEnd,
      graceUntil,
      features,
      now,
      trialEnd,
      now,
      now,
      now
    );

    // 5. Link device
    this.db.prepare(`
      INSERT INTO license_devices (id, license_id, device_id, activated_at, status, last_seen_at)
      VALUES (?, ?, ?, ?, 'ACTIVE', ?)
    `).run('ldev-' + crypto.randomBytes(6).toString('hex'), licenseId, deviceId, now, now);

    // 6. Record activation telemetry
    this.recordTelemetry('activation', orgId, userId, deviceId, { pilot_type: 'starter_trial', duration_days: durationDays });

    return {
      success: true,
      org_id: orgId,
      user_id: userId,
      device_id: deviceId,
      license_id: licenseId,
      trial_start: now,
      trial_end: trialEnd,
      trial_status: 'ACTIVE'
    };
  }

  public listPilots() {
    const rows = this.db.prepare(`
      SELECT o.org_id, o.name as org_name, o.suspended, o.created_at,
             l.license_id, l.status as license_status, l.expires_at, l.trial_start, l.trial_end, l.trial_status,
             l.scan_limit, l.scans_used, l.max_devices, l.max_users,
             (SELECT COUNT(*) FROM users u WHERE u.org_id = o.org_id) as current_users,
             (SELECT COUNT(*) FROM devices d WHERE d.org_id = o.org_id AND d.revoked = 0) as current_devices,
             (SELECT COUNT(*) FROM scans s WHERE s.org_id = o.org_id) as total_scans_run
      FROM organizations o
      LEFT JOIN licenses l ON l.organization_id = o.org_id
      WHERE l.plan_id = 'plan-starter-trial' OR l.status = 'TRIAL'
      ORDER BY o.created_at DESC
    `).all() as any[];

    const now = Date.now();
    return rows.map(r => {
      const trialEnd = r.trial_end ? new Date(r.trial_end).getTime() : now;
      const daysRemaining = Math.max(0, Math.ceil((trialEnd - now) / (24 * 3600 * 1000)));
      return {
        ...r,
        days_remaining: daysRemaining,
        feature_flags: ['LOCAL_SCANNING', 'AUDIT_ENGINE', 'CENTRAL_HISTORY']
      };
    });
  }

  public extendPilotTrial(orgId: string, additionalDays: number, adminUserId: string) {
    const lic = this.db.prepare('SELECT * FROM licenses WHERE organization_id = ? ORDER BY created_at DESC LIMIT 1').get(orgId) as any;
    if (!lic) throw new Error('No license found for organization');

    const currentExpiry = new Date(lic.expires_at).getTime();
    const newExpiry = new Date(Math.max(Date.now(), currentExpiry) + additionalDays * 24 * 3600 * 1000).toISOString();
    const newGrace = new Date(new Date(newExpiry).getTime() + 7 * 24 * 3600 * 1000).toISOString();

    this.db.prepare(`
      UPDATE licenses
      SET expires_at = ?, trial_end = ?, grace_until = ?, updated_at = ?
      WHERE license_id = ?
    `).run(newExpiry, newExpiry, newGrace, new Date().toISOString(), lic.license_id);

    this.recordTelemetry('activation', orgId, adminUserId, undefined, { action: 'trial_extended', additional_days: additionalDays, new_expiry: newExpiry });

    return { success: true, new_trial_end: newExpiry };
  }

  public convertPilotToPaid(orgId: string, planId: string, adminUserId: string) {
    const lic = this.db.prepare('SELECT * FROM licenses WHERE organization_id = ? ORDER BY created_at DESC LIMIT 1').get(orgId) as any;
    if (!lic) throw new Error('No license found for organization');

    const plan = this.db.prepare('SELECT * FROM plans WHERE plan_id = ?').get(planId) as any;
    if (!plan) throw new Error('Invalid plan ID');

    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString();

    this.db.prepare(`
      UPDATE licenses
      SET plan_id = ?, status = 'ACTIVE', trial_status = 'CONVERTED',
          max_users = ?, max_devices = ?, scan_limit = ?, feature_flags = ?,
          expires_at = ?, updated_at = ?
      WHERE license_id = ?
    `).run(
      planId,
      plan.max_users,
      plan.max_devices,
      plan.scan_limit,
      plan.feature_flags,
      expiresAt,
      now,
      lic.license_id
    );

    this.recordTelemetry('activation', orgId, adminUserId, undefined, { action: 'converted_to_paid', plan_id: planId });

    return { success: true, plan_id: planId, status: 'ACTIVE' };
  }
}
