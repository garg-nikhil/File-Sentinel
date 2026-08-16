import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import { getDatabase } from './db.js';
import { PilotService } from './pilotService.js';

export type LicenseStatus =
  | 'TRIAL'
  | 'ACTIVE'
  | 'PAST_DUE'
  | 'GRACE_PERIOD'
  | 'SUSPENDED'
  | 'EXPIRED'
  | 'CANCELLED';

export type FeatureEntitlement =
  | 'LOCAL_SCANNING'
  | 'AUDIT_ENGINE'
  | 'MULTI_FOLDER_SCAN'
  | 'CLOUD_EVIDENCE_UPLOAD'
  | 'CENTRAL_HISTORY'
  | 'ADVANCED_REPORTING'
  | 'API_ACCESS';

export type LicenseUIState =
  | 'ACTIVE'
  | 'TRIAL'
  | 'EXPIRING_SOON'
  | 'OFFLINE_GRACE'
  | 'EXPIRED'
  | 'DEVICE_LIMIT_REACHED'
  | 'SCAN_LIMIT_REACHED'
  | 'SUSPENDED'
  | 'CANCELLED'
  | 'NO_LICENSE';

export interface PlanRecord {
  plan_id: string;
  name: string;
  max_users: number;
  max_devices: number;
  scan_limit: number; // -1 for unlimited
  feature_flags: string[];
  created_at: string;
}

export interface LicenseRecord {
  license_id: string;
  organization_id: string;
  plan_id: string;
  status: LicenseStatus;
  issued_at: string;
  starts_at: string;
  expires_at: string;
  grace_until: string | null;
  max_users: number;
  max_devices: number;
  scan_limit: number;
  scans_used: number;
  feature_flags: string[];
  trial_start?: string | null;
  trial_end?: string | null;
  trial_status?: string | null;
  created_at: string;
  updated_at: string;
  last_validated_at: string | null;
}

export interface LicenseValidationResult {
  valid: boolean;
  ui_state: LicenseUIState;
  status: LicenseStatus;
  license_id?: string;
  organization_id?: string;
  plan_id?: string;
  error?: string;
  reason?: string;
  days_remaining?: number;
  devices_active?: number;
  max_devices?: number;
  scans_used?: number;
  scan_limit?: number;
  feature_flags?: string[];
  grace_active?: boolean;
}

export class LicensingEngine {
  private db: DatabaseSync;
  private offlineGraceHours: number;

  constructor(db?: DatabaseSync, offlineGraceHours: number = 72) {
    this.db = db || getDatabase();
    this.offlineGraceHours = offlineGraceHours;
  }

  public getDb(): DatabaseSync {
    return this.db;
  }

  public logLicenseEvent(
    licenseId: string,
    orgId: string,
    eventType: string,
    details?: Record<string, any>,
    actorId?: string
  ): void {
    const id = 'le-' + crypto.randomBytes(12).toString('hex');
    const now = new Date().toISOString();
    try {
      this.db.prepare(`
        INSERT INTO license_events (id, license_id, org_id, event_type, timestamp, details, actor_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(id, licenseId, orgId, eventType, now, details ? JSON.stringify(details) : null, actorId || null);
    } catch (err) {
      console.error('[LicensingEngine] Failed to log license event:', err);
    }
  }

  public getLicenseForOrg(orgId: string): LicenseRecord | null {
    const row = this.db.prepare(`
      SELECT * FROM licenses 
      WHERE organization_id = ?
      ORDER BY created_at DESC 
      LIMIT 1
    `).get(orgId) as any;

    if (!row) return null;

    let featureFlags: string[] = [];
    try {
      featureFlags = typeof row.feature_flags === 'string' ? JSON.parse(row.feature_flags) : row.feature_flags;
    } catch (e) {
      featureFlags = [];
    }

    return {
      license_id: row.license_id,
      organization_id: row.organization_id,
      plan_id: row.plan_id,
      status: row.status as LicenseStatus,
      issued_at: row.issued_at,
      starts_at: row.starts_at,
      expires_at: row.expires_at,
      grace_until: row.grace_until,
      max_users: row.max_users,
      max_devices: row.max_devices,
      scan_limit: row.scan_limit,
      scans_used: row.scans_used || 0,
      feature_flags: featureFlags,
      trial_start: row.trial_start,
      trial_end: row.trial_end,
      trial_status: row.trial_status,
      created_at: row.created_at,
      updated_at: row.updated_at,
      last_validated_at: row.last_validated_at
    };
  }

  public getActiveDeviceCount(licenseId: string): number {
    const row = this.db.prepare(`
      SELECT COUNT(*) as count FROM license_devices
      WHERE license_id = ? AND status = 'ACTIVE'
    `).get(licenseId) as { count: number };
    return row?.count || 0;
  }

  public validateLicense(
    orgId: string,
    options?: {
      deviceId?: string;
      requiredFeature?: FeatureEntitlement;
      isStartingScan?: boolean;
      isOfflineCheck?: boolean;
      clientReportedTime?: string;
      actorId?: string;
    }
  ): LicenseValidationResult {
    const license = this.getLicenseForOrg(orgId);
    if (!license) {
      return {
        valid: false,
        ui_state: 'NO_LICENSE',
        status: 'EXPIRED',
        error: 'No license found for organization'
      };
    }

    const now = new Date();
    const nowIso = now.toISOString();

    // 1. Clock Manipulation Detection
    if (options?.clientReportedTime) {
      const clientTime = new Date(options.clientReportedTime);
      const skewMs = Math.abs(now.getTime() - clientTime.getTime());
      if (skewMs > 5 * 60 * 1000) { // > 5 minutes skew
        this.logLicenseEvent(
          license.license_id,
          orgId,
          'CLOCK_SKEW_DETECTED',
          { client_time: options.clientReportedTime, server_time: nowIso, skew_ms: skewMs },
          options.actorId
        );
      }
    }

    // Monotonic server timestamp check against last_validated_at
    if (license.last_validated_at) {
      const lastValidated = new Date(license.last_validated_at);
      if (now.getTime() < lastValidated.getTime() - 60000) {
        this.logLicenseEvent(
          license.license_id,
          orgId,
          'SERVER_CLOCK_REGRESSION_DETECTED',
          { last_validated: license.last_validated_at, current_time: nowIso },
          options.actorId
        );
      }
    }

    // Update last_validated_at
    this.db.prepare('UPDATE licenses SET last_validated_at = ? WHERE license_id = ?').run(nowIso, license.license_id);

    // 2. Explicit terminal / non-functional statuses
    if (license.status === 'SUSPENDED') {
      return {
        valid: false,
        ui_state: 'SUSPENDED',
        status: 'SUSPENDED',
        license_id: license.license_id,
        organization_id: orgId,
        error: 'License has been suspended by administration'
      };
    }

    if (license.status === 'CANCELLED') {
      return {
        valid: false,
        ui_state: 'CANCELLED',
        status: 'CANCELLED',
        license_id: license.license_id,
        organization_id: orgId,
        error: 'License has been cancelled'
      };
    }

    // 3. Expiration & Grace Period Transitions
    const expiresAt = new Date(license.expires_at);
    const graceUntil = license.grace_until ? new Date(license.grace_until) : null;
    let currentStatus = license.status;
    let graceActive = false;

    if (now.getTime() > expiresAt.getTime()) {
      if (graceUntil && now.getTime() <= graceUntil.getTime()) {
        graceActive = true;
        if (currentStatus !== 'GRACE_PERIOD') {
          currentStatus = 'GRACE_PERIOD';
          this.db.prepare('UPDATE licenses SET status = ?, updated_at = ? WHERE license_id = ?')
            .run('GRACE_PERIOD', nowIso, license.license_id);
          this.logLicenseEvent(license.license_id, orgId, 'GRACE_PERIOD_ENTERED', { expires_at: license.expires_at, grace_until: license.grace_until }, options?.actorId);
        }
      } else {
        if (currentStatus !== 'EXPIRED') {
          currentStatus = 'EXPIRED';
          this.db.prepare('UPDATE licenses SET status = ?, updated_at = ? WHERE license_id = ?')
            .run('EXPIRED', nowIso, license.license_id);
          this.logLicenseEvent(license.license_id, orgId, 'LICENSE_EXPIRED', { expires_at: license.expires_at }, options?.actorId);
        }
        return {
          valid: false,
          ui_state: 'EXPIRED',
          status: 'EXPIRED',
          license_id: license.license_id,
          organization_id: orgId,
          error: 'License has expired'
        };
      }
    }

    // 4. Offline mode validation check
    if (options?.isOfflineCheck) {
      if (license.last_validated_at) {
        const lastVal = new Date(license.last_validated_at).getTime();
        const maxOfflineMs = this.offlineGraceHours * 3600 * 1000;
        if (now.getTime() - lastVal > maxOfflineMs) {
          return {
            valid: false,
            ui_state: 'EXPIRED',
            status: currentStatus,
            license_id: license.license_id,
            organization_id: orgId,
            error: `Offline grace period (${this.offlineGraceHours}h) exceeded. Internet connection required to revalidate license.`
          };
        }
      }
    }

    // 5. Device Verification & Slot Availability
    const activeDeviceCount = this.getActiveDeviceCount(license.license_id);
    if (options?.deviceId) {
      const devRow = this.db.prepare(`
        SELECT * FROM license_devices
        WHERE license_id = ? AND device_id = ?
      `).get(license.license_id, options.deviceId) as any;

      if (!devRow || devRow.status !== 'ACTIVE') {
        // Attempt automatic activation if device slots are available
        if (activeDeviceCount < license.max_devices) {
          this.activateDevice(license.license_id, orgId, options.deviceId, options.actorId);
        } else {
          return {
            valid: false,
            ui_state: 'DEVICE_LIMIT_REACHED',
            status: currentStatus,
            license_id: license.license_id,
            organization_id: orgId,
            devices_active: activeDeviceCount,
            max_devices: license.max_devices,
            error: `Device limit reached (${activeDeviceCount}/${license.max_devices}). Deactivate another device to activate this workstation.`
          };
        }
      } else {
        // Update device last_seen_at
        this.db.prepare('UPDATE license_devices SET last_seen_at = ? WHERE id = ?').run(nowIso, devRow.id);
      }
    }

    // 6. Scan Limits / Quota Verification
    if (options?.isStartingScan) {
      if (license.scan_limit !== -1 && license.scans_used >= license.scan_limit) {
        return {
          valid: false,
          ui_state: 'SCAN_LIMIT_REACHED',
          status: currentStatus,
          license_id: license.license_id,
          organization_id: orgId,
          scans_used: license.scans_used,
          scan_limit: license.scan_limit,
          error: `Scan quota reached (${license.scans_used}/${license.scan_limit} scans used). Upgrade your subscription plan for additional scans.`
        };
      }
    }

    // 7. Feature Entitlements
    if (options?.requiredFeature) {
      if (!license.feature_flags.includes(options.requiredFeature)) {
        return {
          valid: false,
          ui_state: currentStatus === 'TRIAL' ? 'TRIAL' : 'ACTIVE',
          status: currentStatus,
          license_id: license.license_id,
          organization_id: orgId,
          error: `Feature '${options.requiredFeature}' is not included in your current plan (${license.plan_id}).`
        };
      }
    }

    // 8. Calculate UI State
    const daysRemaining = Math.max(0, Math.ceil((expiresAt.getTime() - now.getTime()) / (24 * 3600 * 1000)));
    let uiState: LicenseUIState = 'ACTIVE';

    if (graceActive) {
      uiState = 'OFFLINE_GRACE';
    } else if (currentStatus === 'TRIAL') {
      uiState = 'TRIAL';
    } else if (daysRemaining <= 7) {
      uiState = 'EXPIRING_SOON';
    } else {
      uiState = 'ACTIVE';
    }

    return {
      valid: true,
      ui_state: uiState,
      status: currentStatus,
      license_id: license.license_id,
      organization_id: orgId,
      plan_id: license.plan_id,
      days_remaining: daysRemaining,
      devices_active: activeDeviceCount,
      max_devices: license.max_devices,
      scans_used: license.scans_used,
      scan_limit: license.scan_limit,
      feature_flags: license.feature_flags,
      grace_active: graceActive
    };
  }

  public activateDevice(
    licenseId: string,
    orgId: string,
    deviceId: string,
    actorId?: string
  ): { success: boolean; message?: string } {
    const license = this.db.prepare('SELECT * FROM licenses WHERE license_id = ? AND organization_id = ?').get(licenseId, orgId) as any;
    if (!license) {
      return { success: false, message: 'License not found in organization' };
    }

    const device = this.db.prepare('SELECT * FROM devices WHERE device_id = ? AND org_id = ?').get(deviceId, orgId) as any;
    if (!device || device.revoked === 1) {
      return { success: false, message: 'Device is not registered or is revoked' };
    }

    const existingLink = this.db.prepare('SELECT * FROM license_devices WHERE license_id = ? AND device_id = ?').get(licenseId, deviceId) as any;
    const now = new Date().toISOString();

    if (existingLink && existingLink.status === 'ACTIVE') {
      return { success: true, message: 'Device is already active' };
    }

    const activeCount = this.getActiveDeviceCount(licenseId);
    if (activeCount >= license.max_devices) {
      return { success: false, message: `Maximum device limit reached (${activeCount}/${license.max_devices})` };
    }

    if (existingLink) {
      this.db.prepare('UPDATE license_devices SET status = ?, last_seen_at = ? WHERE id = ?').run('ACTIVE', now, existingLink.id);
    } else {
      const id = 'ldev-' + crypto.randomBytes(12).toString('hex');
      this.db.prepare(`
        INSERT INTO license_devices (id, license_id, device_id, activated_at, status, last_seen_at)
        VALUES (?, ?, ?, ?, 'ACTIVE', ?)
      `).run(id, licenseId, deviceId, now, now);
    }

    this.logLicenseEvent(licenseId, orgId, 'DEVICE_ACTIVATED', { device_id: deviceId }, actorId);
    try {
      const pilotService = new PilotService(this.db);
      pilotService.recordTelemetry('device_added', orgId, actorId, deviceId, { license_id: licenseId });
    } catch {}
    return { success: true, message: 'Device activated successfully' };
  }

  public deactivateDevice(
    licenseId: string,
    orgId: string,
    deviceId: string,
    actorId?: string
  ): { success: boolean; message?: string } {
    const link = this.db.prepare(`
      SELECT ld.* FROM license_devices ld
      JOIN licenses l ON ld.license_id = l.license_id
      WHERE ld.license_id = ? AND l.organization_id = ? AND ld.device_id = ?
    `).get(licenseId, orgId, deviceId) as any;

    if (!link) {
      return { success: false, message: 'Active device binding not found' };
    }

    this.db.prepare("UPDATE license_devices SET status = 'DEACTIVATED' WHERE id = ?").run(link.id);
    this.logLicenseEvent(licenseId, orgId, 'DEVICE_DEACTIVATED', { device_id: deviceId }, actorId);
    try {
      const pilotService = new PilotService(this.db);
      pilotService.recordTelemetry('device_removed', orgId, actorId, deviceId, { license_id: licenseId });
    } catch {}
    return { success: true, message: 'Device deactivated successfully' };
  }

  public consumeScanQuota(licenseId: string, count: number = 1): void {
    try {
      this.db.prepare(`
        UPDATE licenses 
        SET scans_used = scans_used + ?, updated_at = ?
        WHERE license_id = ?
      `).run(count, new Date().toISOString(), licenseId);
    } catch (e) {
      console.error('[LicensingEngine] Failed to increment scan count:', e);
    }
  }

  // --- INTERNAL ADMIN API METHODS ---
  public issueLicense(params: {
    organizationId: string;
    planId: string;
    status?: LicenseStatus;
    durationDays?: number;
    gracePeriodDays?: number;
    customMaxUsers?: number;
    customMaxDevices?: number;
    customScanLimit?: number;
    customFeatureFlags?: string[];
    actorId?: string;
  }): LicenseRecord {
    const plan = this.db.prepare('SELECT * FROM plans WHERE plan_id = ?').get(params.planId) as any;
    if (!plan) {
      throw new Error(`Plan '${params.planId}' not found`);
    }

    const org = this.db.prepare('SELECT * FROM organizations WHERE org_id = ?').get(params.organizationId) as any;
    if (!org) {
      throw new Error(`Organization '${params.organizationId}' not found`);
    }

    const licenseId = 'lic-' + crypto.randomBytes(12).toString('hex');
    const now = new Date();
    const nowIso = now.toISOString();
    const durationDays = params.durationDays || (params.status === 'TRIAL' ? 14 : 365);
    const graceDays = params.gracePeriodDays ?? 7;

    const startsAt = nowIso;
    const expiresAt = new Date(now.getTime() + durationDays * 24 * 3600 * 1000).toISOString();
    const graceUntil = new Date(new Date(expiresAt).getTime() + graceDays * 24 * 3600 * 1000).toISOString();

    const maxUsers = params.customMaxUsers ?? plan.max_users;
    const maxDevices = params.customMaxDevices ?? plan.max_devices;
    const scanLimit = params.customScanLimit ?? plan.scan_limit;
    const featureFlags = params.customFeatureFlags ?? (typeof plan.feature_flags === 'string' ? JSON.parse(plan.feature_flags) : plan.feature_flags);

    this.db.prepare(`
      INSERT INTO licenses (
        license_id, organization_id, plan_id, status, issued_at, starts_at, expires_at,
        grace_until, max_users, max_devices, scan_limit, scans_used, feature_flags,
        created_at, updated_at, last_validated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
    `).run(
      licenseId,
      params.organizationId,
      params.planId,
      params.status || (params.planId.includes('trial') ? 'TRIAL' : 'ACTIVE'),
      nowIso,
      startsAt,
      expiresAt,
      graceUntil,
      maxUsers,
      maxDevices,
      scanLimit,
      JSON.stringify(featureFlags),
      nowIso,
      nowIso,
      nowIso
    );

    this.logLicenseEvent(licenseId, params.organizationId, 'LICENSE_ISSUED', { plan_id: params.planId, expires_at: expiresAt }, params.actorId);

    return {
      license_id: licenseId,
      organization_id: params.organizationId,
      plan_id: params.planId,
      status: (params.status || 'ACTIVE') as LicenseStatus,
      issued_at: nowIso,
      starts_at: startsAt,
      expires_at: expiresAt,
      grace_until: graceUntil,
      max_users: maxUsers,
      max_devices: maxDevices,
      scan_limit: scanLimit,
      scans_used: 0,
      feature_flags: featureFlags,
      created_at: nowIso,
      updated_at: nowIso,
      last_validated_at: nowIso
    };
  }

  public updateLicenseStatus(
    licenseId: string,
    status: LicenseStatus,
    details?: Record<string, any>,
    actorId?: string
  ): void {
    const license = this.db.prepare('SELECT * FROM licenses WHERE license_id = ?').get(licenseId) as any;
    if (!license) throw new Error('License not found');

    const nowIso = new Date().toISOString();
    this.db.prepare('UPDATE licenses SET status = ?, updated_at = ? WHERE license_id = ?').run(status, nowIso, licenseId);
    this.logLicenseEvent(licenseId, license.organization_id, `LICENSE_STATUS_${status}`, details, actorId);
  }

  public extendLicenseExpiration(
    licenseId: string,
    additionalDays: number,
    actorId?: string
  ): { new_expires_at: string; new_grace_until: string } {
    const license = this.db.prepare('SELECT * FROM licenses WHERE license_id = ?').get(licenseId) as any;
    if (!license) throw new Error('License not found');

    const currentExpires = new Date(license.expires_at);
    const newExpires = new Date(Math.max(Date.now(), currentExpires.getTime()) + additionalDays * 24 * 3600 * 1000);
    const newExpiresIso = newExpires.toISOString();
    const newGraceUntil = new Date(newExpires.getTime() + 7 * 24 * 3600 * 1000).toISOString();
    const nowIso = new Date().toISOString();

    this.db.prepare(`
      UPDATE licenses 
      SET expires_at = ?, grace_until = ?, status = 'ACTIVE', updated_at = ?
      WHERE license_id = ?
    `).run(newExpiresIso, newGraceUntil, nowIso, licenseId);

    this.logLicenseEvent(licenseId, license.organization_id, 'LICENSE_EXTENDED', { additional_days: additionalDays, new_expires_at: newExpiresIso }, actorId);

    return { new_expires_at: newExpiresIso, new_grace_until: newGraceUntil };
  }
}

export const defaultLicensingEngine = new LicensingEngine();
