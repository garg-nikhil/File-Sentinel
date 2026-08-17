import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import { logSecurityEvent, hashPassword } from '../auth.js';

export class AdminService {
  private db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
  }

  // Organizations
  public searchOrganizations(search?: string) {
    let query = `
      SELECT o.org_id, o.name, o.suspended, o.created_at,
             (SELECT COUNT(*) FROM users u WHERE u.org_id = o.org_id) as user_count,
             (SELECT COUNT(*) FROM devices d WHERE d.org_id = o.org_id) as device_count,
             (SELECT l.status FROM licenses l WHERE l.organization_id = o.org_id ORDER BY l.issued_at DESC LIMIT 1) as license_status,
             (SELECT s.status FROM subscriptions s WHERE s.org_id = o.org_id ORDER BY s.created_at DESC LIMIT 1) as subscription_status
      FROM organizations o
    `;
    const params: any[] = [];
    if (search && search.trim() !== '') {
      query += ` WHERE o.name LIKE ? OR o.org_id LIKE ? `;
      params.push(`%${search}%`, `%${search}%`);
    }
    query += ` ORDER BY o.created_at DESC `;
    return this.db.prepare(query).all(...params);
  }

  public getOrganizationDetails(orgId: string) {
    const org = this.db.prepare('SELECT * FROM organizations WHERE org_id = ?').get(orgId);
    if (!org) return null;

    const users = this.db.prepare('SELECT user_id, username, role, disabled, created_at FROM users WHERE org_id = ?').all(orgId);
    const devices = this.db.prepare('SELECT device_id, device_name, revoked, registered_at FROM devices WHERE org_id = ?').all(orgId);
    const licenses = this.db.prepare('SELECT * FROM licenses WHERE organization_id = ?').all(orgId);
    const subscriptions = this.db.prepare('SELECT * FROM subscriptions WHERE org_id = ?').all(orgId);
    const recentScans = this.db.prepare('SELECT scan_id, start_time, end_time, status, total_files, critical_count, high_count FROM scans WHERE org_id = ? ORDER BY start_time DESC LIMIT 20').all(orgId);
    const scanTelemetry = this.db.prepare('SELECT scan_id, started_at, application_version, files_discovered, overall_score, scan_status FROM scan_telemetry WHERE organization_id = ? ORDER BY started_at DESC LIMIT 20').all(orgId);

    return {
      organization: org,
      users,
      devices,
      licenses,
      subscriptions,
      recent_scans: recentScans,
      scan_telemetry: scanTelemetry
    };
  }

  public suspendOrganization(orgId: string, adminUserId: string) {
    this.db.prepare('UPDATE organizations SET suspended = 1 WHERE org_id = ?').run(orgId);
    logSecurityEvent('ADMIN_ORG_SUSPENDED', 'SUCCESS', orgId, adminUserId, undefined, { orgId }, this.db);
    return { success: true };
  }

  public reactivateOrganization(orgId: string, adminUserId: string) {
    this.db.prepare('UPDATE organizations SET suspended = 0 WHERE org_id = ?').run(orgId);
    logSecurityEvent('ADMIN_ORG_REACTIVATED', 'SUCCESS', orgId, adminUserId, undefined, { orgId }, this.db);
    return { success: true };
  }

  // Users
  public listUsers() {
    return this.db.prepare(`
      SELECT u.user_id, u.org_id, o.name as org_name, u.username, u.role, u.disabled, u.created_at
      FROM users u
      JOIN organizations o ON u.org_id = o.org_id
      ORDER BY u.created_at DESC
    `).all();
  }

  public setUserDisabled(userId: string, disabled: number, adminUserId: string) {
    this.db.prepare('UPDATE users SET disabled = ? WHERE user_id = ?').run(disabled, userId);
    const user = this.db.prepare('SELECT org_id, username FROM users WHERE user_id = ?').get(userId) as any;
    const eventType = disabled ? 'ADMIN_USER_DISABLED' : 'ADMIN_USER_ENABLED';
    logSecurityEvent(eventType, 'SUCCESS', user?.org_id, adminUserId, undefined, { targetUserId: userId, username: user?.username }, this.db);
    return { success: true };
  }

  public resetUserPassword(userId: string, adminUserId: string) {
    const user = this.db.prepare('SELECT org_id, username FROM users WHERE user_id = ?').get(userId) as any;
    if (!user) {
      throw new Error('User not found');
    }
    const tempPassword = 'Temp!' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const newHash = hashPassword(tempPassword);
    this.db.prepare('UPDATE users SET password_hash = ? WHERE user_id = ?').run(newHash, userId);
    logSecurityEvent('ADMIN_USER_PASSWORD_RESET', 'SUCCESS', user.org_id, adminUserId, undefined, { targetUserId: userId, username: user.username }, this.db);
    return { success: true, temporary_password: tempPassword };
  }

  // Devices
  public listDevices() {
    return this.db.prepare(`
      SELECT d.device_id, d.org_id, o.name as org_name, d.device_name, d.revoked, d.registered_at
      FROM devices d
      JOIN organizations o ON d.org_id = o.org_id
      ORDER BY d.registered_at DESC
    `).all();
  }

  public setDeviceRevoked(deviceId: string, revoked: number, adminUserId: string) {
    const dev = this.db.prepare('SELECT org_id, device_name FROM devices WHERE device_id = ?').get(deviceId) as any;
    this.db.prepare('UPDATE devices SET revoked = ? WHERE device_id = ?').run(revoked, deviceId);
    const eventType = revoked ? 'ADMIN_DEVICE_REVOKED' : 'ADMIN_DEVICE_REACTIVATED';
    logSecurityEvent(eventType, 'SUCCESS', dev?.org_id, adminUserId, deviceId, { deviceName: dev?.device_name }, this.db);
    return { success: true };
  }

  // Licenses
  public listLicenses() {
    return this.db.prepare(`
      SELECT l.*, o.name as organization_name, p.name as plan_name
      FROM licenses l
      JOIN organizations o ON l.organization_id = o.org_id
      JOIN plans p ON l.plan_id = p.plan_id
      ORDER BY l.issued_at DESC
    `).all();
  }

  public issueLicense(params: {
    organization_id: string;
    plan_id: string;
    status?: string;
    duration_days?: number;
    max_users?: number;
    max_devices?: number;
    scan_limit?: number;
    admin_user_id: string;
  }) {
    const licenseId = 'lic-' + crypto.randomBytes(6).toString('hex');
    const now = new Date().toISOString();
    const days = params.duration_days || 365;
    const expiresAt = new Date(Date.now() + days * 24 * 3600 * 1000).toISOString();
    const graceUntil = new Date(Date.now() + (days + 7) * 24 * 3600 * 1000).toISOString();

    const plan = this.db.prepare('SELECT * FROM plans WHERE plan_id = ?').get(params.plan_id) as any;
    if (!plan) throw new Error('Invalid plan ID');

    const maxUsers = params.max_users ?? plan.max_users;
    const maxDevices = params.max_devices ?? plan.max_devices;
    const scanLimit = params.scan_limit ?? plan.scan_limit;
    const licenseStatus = params.status || 'ACTIVE';

    this.db.prepare(`
      INSERT INTO licenses (
        license_id, organization_id, plan_id, status, issued_at, starts_at, expires_at,
        grace_until, max_users, max_devices, scan_limit, scans_used, feature_flags,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
    `).run(
      licenseId,
      params.organization_id,
      params.plan_id,
      licenseStatus,
      now,
      now,
      expiresAt,
      graceUntil,
      maxUsers,
      maxDevices,
      scanLimit,
      plan.feature_flags,
      now,
      now
    );

    logSecurityEvent('ADMIN_LICENSE_ISSUED', 'SUCCESS', params.organization_id, params.admin_user_id, undefined, { licenseId, planId: params.plan_id }, this.db);
    return { success: true, license_id: licenseId };
  }

  public updateLicenseStatus(licenseId: string, status: 'ACTIVE' | 'SUSPENDED' | 'REVOKED', adminUserId: string) {
    const lic = this.db.prepare('SELECT organization_id FROM licenses WHERE license_id = ?').get(licenseId) as any;
    this.db.prepare('UPDATE licenses SET status = ?, updated_at = ? WHERE license_id = ?').run(status, new Date().toISOString(), licenseId);
    logSecurityEvent('ADMIN_LICENSE_STATUS_UPDATED', 'SUCCESS', lic?.organization_id, adminUserId, undefined, { licenseId, status }, this.db);
    return { success: true };
  }

  public extendLicense(licenseId: string, additionalDays: number, adminUserId: string) {
    const lic = this.db.prepare('SELECT organization_id, expires_at FROM licenses WHERE license_id = ?').get(licenseId) as any;
    if (!lic) throw new Error('License not found');
    const currentExpiry = new Date(lic.expires_at).getTime();
    const newExpiry = new Date(Math.max(Date.now(), currentExpiry) + additionalDays * 24 * 3600 * 1000).toISOString();
    const newGrace = new Date(new Date(newExpiry).getTime() + 7 * 24 * 3600 * 1000).toISOString();

    this.db.prepare('UPDATE licenses SET expires_at = ?, grace_until = ?, status = ?, updated_at = ? WHERE license_id = ?').run(newExpiry, newGrace, 'ACTIVE', new Date().toISOString(), licenseId);
    logSecurityEvent('ADMIN_LICENSE_EXTENDED', 'SUCCESS', lic.organization_id, adminUserId, undefined, { licenseId, newExpiry }, this.db);
    return { success: true, new_expires_at: newExpiry };
  }

  public changeLicensePlan(licenseId: string, newPlanId: string, adminUserId: string) {
    const lic = this.db.prepare('SELECT organization_id FROM licenses WHERE license_id = ?').get(licenseId) as any;
    const plan = this.db.prepare('SELECT * FROM plans WHERE plan_id = ?').get(newPlanId) as any;
    if (!lic || !plan) throw new Error('License or Plan not found');

    this.db.prepare(`
      UPDATE licenses
      SET plan_id = ?, max_users = ?, max_devices = ?, scan_limit = ?, feature_flags = ?, updated_at = ?
      WHERE license_id = ?
    `).run(newPlanId, plan.max_users, plan.max_devices, plan.scan_limit, plan.feature_flags, new Date().toISOString(), licenseId);

    logSecurityEvent('ADMIN_LICENSE_PLAN_CHANGED', 'SUCCESS', lic.organization_id, adminUserId, undefined, { licenseId, newPlanId }, this.db);
    return { success: true };
  }

  // Subscriptions
  public listSubscriptions() {
    return this.db.prepare(`
      SELECT s.*, o.name as organization_name, p.name as plan_name, bc.email as billing_email
      FROM subscriptions s
      JOIN organizations o ON s.org_id = o.org_id
      JOIN plans p ON s.plan_id = p.plan_id
      LEFT JOIN billing_customers bc ON s.customer_id = bc.customer_id
      ORDER BY s.created_at DESC
    `).all();
  }

  // Usage & Telemetry
  public getUsageOverview() {
    const totalOrgs = (this.db.prepare('SELECT COUNT(*) as count FROM organizations').get() as any).count;
    const totalUsers = (this.db.prepare('SELECT COUNT(*) as count FROM users').get() as any).count;
    const totalDevices = (this.db.prepare('SELECT COUNT(*) as count FROM devices').get() as any).count;
    const totalScans = (this.db.prepare('SELECT COUNT(*) as count FROM scans').get() as any).count;
    const telemetryStats = this.db.prepare(`
      SELECT COUNT(*) as telemetry_records,
             SUM(files_discovered) as total_files_discovered,
             SUM(duration_ms) as total_duration_ms
      FROM scan_telemetry
    `).get();

    return {
      total_organizations: totalOrgs,
      total_users: totalUsers,
      total_devices: totalDevices,
      total_scans: totalScans,
      telemetry: telemetryStats
    };
  }

  // Security Events
  public listSecurityEvents(filters?: { event_type?: string; limit?: number }) {
    let query = 'SELECT * FROM security_audit_events';
    const params: any[] = [];
    if (filters?.event_type) {
      query += ' WHERE event_type LIKE ?';
      params.push(`%${filters.event_type}%`);
    }
    query += ' ORDER BY timestamp DESC LIMIT ?';
    params.push(filters?.limit || 100);
    return this.db.prepare(query).all(...params);
  }

  // System Version & Updates
  public getSystemInfo() {
    return {
      current_application_version: '8.3.0',
      agent_versions_supported: ['8.2.0', '8.2.5', '8.3.0'],
      latest_available_version: '8.3.1',
      update_available: true,
      update_release_notes: 'FileSentinel 8.3.1: Enhanced cryptographic verification integrity and performance optimizations.',
      server_time: new Date().toISOString()
    };
  }
}
