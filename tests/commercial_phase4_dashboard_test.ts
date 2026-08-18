import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { TelemetryService } from '../backend/telemetry.ts';

test('COMMERCIALIZATION PHASE 4: Vendor Cloud Dashboard & Tenant Isolation Test Suite', async (t) => {
  const db = new DatabaseSync(':memory:');

  // Initialize DB tables
  db.exec(`
    CREATE TABLE IF NOT EXISTS organizations (
      org_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      user_id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      disabled INTEGER DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS devices (
      device_id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL,
      device_name TEXT NOT NULL,
      revoked INTEGER DEFAULT 0,
      registered_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS license_devices (
      id TEXT PRIMARY KEY,
      license_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      activated_at TEXT NOT NULL,
      status TEXT NOT NULL,
      last_seen_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scan_telemetry (
      scan_id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      started_at TEXT NOT NULL,
      completed_at TEXT NOT NULL,
      duration_ms INTEGER NOT NULL,
      application_version TEXT NOT NULL,
      engine_version TEXT NOT NULL,
      checklist_version TEXT NOT NULL,
      files_discovered INTEGER NOT NULL,
      files_processed INTEGER NOT NULL,
      files_succeeded INTEGER NOT NULL,
      files_failed INTEGER NOT NULL,
      files_rejected_by_resource_limits INTEGER NOT NULL,
      pass_count INTEGER NOT NULL,
      review_count INTEGER NOT NULL,
      fail_count INTEGER NOT NULL,
      evidence_not_found_count INTEGER NOT NULL,
      critical_count INTEGER NOT NULL,
      high_count INTEGER NOT NULL,
      medium_count INTEGER NOT NULL,
      low_count INTEGER NOT NULL,
      overall_score REAL NOT NULL,
      parameters_evaluated INTEGER NOT NULL,
      scan_status TEXT NOT NULL,
      device_telemetry_json TEXT,
      debug_filenames_opt_in INTEGER DEFAULT 0,
      created_at TEXT NOT NULL,
      ip_address TEXT
    );

    CREATE TABLE IF NOT EXISTS telemetry_queue (
      queue_id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      organization_id TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      status TEXT NOT NULL,
      attempts INTEGER DEFAULT 0,
      last_attempt_at TEXT,
      error_message TEXT,
      created_at TEXT NOT NULL,
      synced_at TEXT
    );

    CREATE TABLE IF NOT EXISTS audit_sessions (
      audit_id TEXT PRIMARY KEY,
      scan_id TEXT,
      audit_date TEXT NOT NULL,
      agency_name TEXT NOT NULL,
      auditor_name TEXT NOT NULL,
      status TEXT NOT NULL,
      total_parameters INTEGER DEFAULT 0,
      pass_count INTEGER DEFAULT 0,
      fail_count INTEGER DEFAULT 0,
      review_count INTEGER DEFAULT 0,
      not_found_count INTEGER DEFAULT 0,
      fatal_failures_count INTEGER DEFAULT 0,
      overall_score INTEGER DEFAULT 0,
      max_score INTEGER DEFAULT 200,
      overall_status TEXT NOT NULL,
      category_scores_json TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scans (
      scan_id TEXT PRIMARY KEY,
      org_id TEXT,
      start_time TEXT NOT NULL,
      end_time TEXT,
      status TEXT NOT NULL,
      total_files INTEGER DEFAULT 0
    );
  `);

  // Seed two distinct organizations
  const now = new Date().toISOString();
  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run('org-alpha', 'Alpha Corp', now);
  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run('org-beta', 'Beta Global', now);

  // Seed users for each org
  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)').run(
    'usr-alpha-admin', 'org-alpha', 'alpha_admin', 'hash123', 'ORG_ADMIN', now
  );
  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)').run(
    'usr-beta-admin', 'org-beta', 'beta_admin', 'hash456', 'ORG_ADMIN', now
  );

  // Seed devices for each org
  db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 0, ?)').run(
    'dev-alpha-01', 'org-alpha', 'Alpha Workstation 1', now
  );
  db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 0, ?)').run(
    'dev-beta-01', 'org-beta', 'Beta Laptop 1', now
  );

  const telemetryService = new TelemetryService(db);

  await t.test('1. Overview calculations for Org Alpha and Org Beta', async () => {
    // Record scans for Org Alpha
    telemetryService.recordScanTelemetry({
      scan_id: 'scan-alpha-1',
      organization_id: 'org-alpha',
      user_id: 'usr-alpha-admin',
      device_id: 'dev-alpha-01',
      started_at: '2026-08-10T10:00:00Z',
      completed_at: '2026-08-10T10:01:00Z',
      duration_ms: 60000,
      application_version: '1.0.0',
      engine_version: '1.0.0',
      checklist_version: '2026.1',
      files_discovered: 50,
      files_processed: 50,
      files_succeeded: 50,
      files_failed: 0,
      files_rejected_by_resource_limits: 0,
      pass_count: 20,
      review_count: 5,
      fail_count: 2,
      evidence_not_found_count: 1,
      critical_count: 1,
      high_count: 1,
      medium_count: 2,
      low_count: 3,
      overall_score: 75.0,
      parameters_evaluated: 28,
      scan_status: 'COMPLETED'
    });

    telemetryService.recordScanTelemetry({
      scan_id: 'scan-alpha-2',
      organization_id: 'org-alpha',
      user_id: 'usr-alpha-admin',
      device_id: 'dev-alpha-01',
      started_at: '2026-08-15T12:00:00Z',
      completed_at: '2026-08-15T12:01:00Z',
      duration_ms: 60000,
      application_version: '1.0.0',
      engine_version: '1.0.0',
      checklist_version: '2026.1',
      files_discovered: 80,
      files_processed: 80,
      files_succeeded: 80,
      files_failed: 0,
      files_rejected_by_resource_limits: 0,
      pass_count: 25,
      review_count: 2,
      fail_count: 1,
      evidence_not_found_count: 0,
      critical_count: 0,
      high_count: 1,
      medium_count: 1,
      low_count: 2,
      overall_score: 90.0,
      parameters_evaluated: 28,
      scan_status: 'COMPLETED'
    });

    // Record scan for Org Beta
    telemetryService.recordScanTelemetry({
      scan_id: 'scan-beta-1',
      organization_id: 'org-beta',
      user_id: 'usr-beta-admin',
      device_id: 'dev-beta-01',
      started_at: '2026-08-16T14:00:00Z',
      completed_at: '2026-08-16T14:01:00Z',
      duration_ms: 60000,
      application_version: '1.0.0',
      engine_version: '1.0.0',
      checklist_version: '2026.1',
      files_discovered: 10,
      files_processed: 10,
      files_succeeded: 10,
      files_failed: 0,
      files_rejected_by_resource_limits: 0,
      pass_count: 5,
      review_count: 5,
      fail_count: 5,
      evidence_not_found_count: 5,
      critical_count: 3,
      high_count: 2,
      medium_count: 1,
      low_count: 1,
      overall_score: 40.0,
      parameters_evaluated: 20,
      scan_status: 'COMPLETED'
    });

    const alphaOverview = telemetryService.getDashboardOverview('org-alpha');
    assert.equal(alphaOverview.total_scans, 2);
    assert.equal(alphaOverview.current_score, 90.0);
    assert.equal(alphaOverview.previous_score, 75.0);
    assert.equal(alphaOverview.score_change, 15.0);
    assert.equal(alphaOverview.files_scanned, 130);
    assert.equal(alphaOverview.pass_count, 45); // 20 + 25
    assert.equal(alphaOverview.fail_count, 3);  // 2 + 1
    assert.equal(alphaOverview.critical_count, 1); // 1 + 0

    const betaOverview = telemetryService.getDashboardOverview('org-beta');
    assert.equal(betaOverview.total_scans, 1);
    assert.equal(betaOverview.current_score, 40.0);
    assert.equal(betaOverview.files_scanned, 10);
    assert.equal(betaOverview.critical_count, 3);
  });

  await t.test('2. Tenant Isolation: Org Alpha cannot access Org Beta scan telemetry', async () => {
    const alphaHistory = telemetryService.getScanHistory('org-alpha');
    assert.equal(alphaHistory.length, 2);
    assert.ok(alphaHistory.every(s => s.organization_id === 'org-alpha'));
    assert.ok(!alphaHistory.some(s => s.scan_id === 'scan-beta-1'));

    const betaHistory = telemetryService.getScanHistory('org-beta');
    assert.equal(betaHistory.length, 1);
    assert.equal(betaHistory[0].scan_id, 'scan-beta-1');
    assert.equal(betaHistory[0].organization_id, 'org-beta');

    // Attempting direct retrieval by scanId
    const crossRetrieve = telemetryService.getScanTelemetry('org-alpha', 'scan-beta-1');
    assert.equal(crossRetrieve, null, 'Cross-tenant scan lookup must return null');
  });

  await t.test('3. Compliance Trend: chronological ordering and isolation', async () => {
    const alphaTrend = telemetryService.getComplianceTrend('org-alpha');
    assert.equal(alphaTrend.length, 2);
    assert.equal(alphaTrend[0].scan_id, 'scan-alpha-1');
    assert.equal(alphaTrend[0].score, 75.0);
    assert.equal(alphaTrend[1].scan_id, 'scan-alpha-2');
    assert.equal(alphaTrend[1].score, 90.0);
  });

  await t.test('4. Report Verification: Validates matched vs cross-tenant vs invalid reports', async () => {
    // 1. Verify existing Alpha scan by Alpha
    const verifiedAlpha = telemetryService.verifyReport('org-alpha', 'scan-alpha-1');
    assert.equal(verifiedAlpha.verified, true);
    assert.equal(verifiedAlpha.match_status, 'MATCHED_TELEMETRY_RECORD');
    assert.equal(verifiedAlpha.overall_score, 75.0);

    // 2. Cross-tenant attempt: Alpha tries to verify Beta report
    const crossVerify = telemetryService.verifyReport('org-alpha', 'scan-beta-1');
    assert.equal(crossVerify.verified, false);
    assert.equal(crossVerify.match_status, 'UNAUTHORIZED_ORGANIZATION');

    // 3. Non-existent report
    const notFoundVerify = telemetryService.verifyReport('org-alpha', 'scan-fake-999');
    assert.equal(notFoundVerify.verified, false);
    assert.equal(notFoundVerify.match_status, 'NOT_FOUND');
  });

  process.exit(0);
});
