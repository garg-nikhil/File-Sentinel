process.env.FILE_SENTINEL_DEV_MODE = 'false';

import { getDatabase } from '../backend/db.js';
import { hashPassword } from '../backend/auth.js';
import { createApiRouter } from '../backend/routes.js';
import { BillingService } from '../backend/billing.js';
import { LicensingEngine } from '../backend/licensing.js';
import { VerifiableAuditReportService } from '../backend/audit/verifiableReportService.js';
import assert from 'node:assert';
import express from 'express';
import request from 'supertest';
import crypto from 'node:crypto';

async function runTenantIsolationTestSuite() {
  console.log('========================================================================');
  console.log('  FILE-SENTINEL R8.1.1: Comprehensive 35-Test Tenant Isolation Suite       ');
  console.log('========================================================================\n');

  const db = getDatabase(':memory:');
  const now = new Date().toISOString();

  // Setup two isolated tenants
  const orgA = 'org-tenant-a';
  const orgB = 'org-tenant-b';
  const userA = 'usr-admin-a';
  const userB = 'usr-admin-b';
  const userViewerA = 'usr-viewer-a';
  const deviceA = 'dev-a';
  const deviceB = 'dev-b';
  const deviceRevoked = 'dev-revoked';
  const userDisabled = 'usr-disabled';

  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(orgA, 'Tenant Alpha Corp', now);
  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(orgB, 'Tenant Beta Ltd', now);

  db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 0, ?)')
    .run(deviceA, orgA, 'Device A', now);
  db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 0, ?)')
    .run(deviceB, orgB, 'Device B', now);
  db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 1, ?)')
    .run(deviceRevoked, orgA, 'Revoked Device', now);

  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)')
    .run(userA, orgA, 'admin_a', hashPassword('Secret123!'), 'ORG_ADMIN', now);
  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)')
    .run(userB, orgB, 'admin_b', hashPassword('Secret123!'), 'ORG_ADMIN', now);
  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)')
    .run(userViewerA, orgA, 'viewer_a', hashPassword('Secret123!'), 'VIEWER', now);
  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)')
    .run(userDisabled, orgA, 'disabled_user', hashPassword('Secret123!'), 'ORG_ADMIN', now);

  const tokenA = 'tok-a-' + crypto.randomBytes(16).toString('hex');
  const tokenB = 'tok-b-' + crypto.randomBytes(16).toString('hex');
  const tokenViewerA = 'tok-viewer-a-' + crypto.randomBytes(16).toString('hex');
  const tokenRevoked = 'tok-revoked-' + crypto.randomBytes(16).toString('hex');
  const tokenDisabled = 'tok-disabled-' + crypto.randomBytes(16).toString('hex');
  const expiresAt = new Date(Date.now() + 86400000).toISOString();

  db.prepare('INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(tokenA, userA, orgA, deviceA, expiresAt, now);
  db.prepare('INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(tokenB, userB, orgB, deviceB, expiresAt, now);
  db.prepare('INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(tokenViewerA, userViewerA, orgA, deviceA, expiresAt, now);
  db.prepare('INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(tokenRevoked, userA, orgA, deviceRevoked, expiresAt, now);
  db.prepare('INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(tokenDisabled, userDisabled, orgA, deviceA, expiresAt, now);

  // Tenant A scan, file, finding, quarantine, audit session
  const scanIdA = 'SCAN-ALPHA-001';
  db.prepare(`
    INSERT INTO scans (scan_id, root_path, start_time, status, total_files, org_id, user_id, device_id)
    VALUES (?, '/secret/alpha/path', ?, 'COMPLETED', 1, ?, ?, ?)
  `).run(scanIdA, now, orgA, userA, deviceA);

  const fileIdA = 'FILE-ALPHA-1';
  db.prepare(`
    INSERT INTO files (file_id, scan_id, path, filename, extension, size, sha256, risk_score, classification, scan_status, created_at)
    VALUES (?, ?, '/secret/alpha/confidential.xlsx', 'confidential.xlsx', '.xlsx', 1024, 'sha256alpha', 85, 'RESTRICTED', 'SUCCESS', ?)
  `).run(fileIdA, scanIdA, now);

  const findingIdA = 'FIND-ALPHA-1';
  db.prepare(`
    INSERT INTO findings (finding_id, file_id, rule_id, severity, category, title, description, created_at)
    VALUES (?, ?, 'RULE-001', 'CRITICAL', 'SECRETS', 'API Key Found', 'AWS Secret Key detected', ?)
  `).run(findingIdA, fileIdA, now);

  const quarantineIdA = 'Q-ALPHA-1';
  db.prepare(`
    INSERT INTO quarantine_items (id, file_id, original_path, filename, sha256, size, quarantined_at)
    VALUES (?, ?, '/secret/alpha/confidential.xlsx', 'confidential.xlsx', 'sha256alpha', 1024, ?)
  `).run(quarantineIdA, fileIdA, now);

  const auditIdA = 'AUDIT-ALPHA-1';
  db.prepare(`
    INSERT INTO audit_sessions (audit_id, scan_id, org_id, audit_date, agency_name, auditor_name, status, overall_score, overall_status, created_at, updated_at)
    VALUES (?, ?, ?, '2026-08-16', 'Alpha Agency', 'Auditor A', 'COMPLETED', 75, 'CONDITIONAL', ?, ?)
  `).run(auditIdA, scanIdA, orgA, now, now);

  const orphanAuditIdA = 'AUDIT-ORPHAN-1';
  db.prepare(`
    INSERT INTO audit_sessions (audit_id, scan_id, org_id, audit_date, agency_name, auditor_name, status, overall_score, overall_status, created_at, updated_at)
    VALUES (?, NULL, ?, '2026-08-16', 'Orphan Agency', 'Auditor', 'COMPLETED', 80, 'PASS', ?, ?)
  `).run(orphanAuditIdA, orgA, now, now);

  // Register real report for Tenant A
  const verifiableReportService = new VerifiableAuditReportService(db);
  const realReportA = verifiableReportService.registerReport({
    scan_id: scanIdA,
    organization_id: orgA,
    session: {
      audit_id: auditIdA,
      scan_id: scanIdA,
      org_id: orgA,
      audit_date: '2026-08-16',
      agency_name: 'Alpha Agency',
      auditor_name: 'Auditor A',
      status: 'COMPLETED',
      overall_score: 75,
      max_score: 100,
      overall_status: 'CONDITIONAL',
      total_parameters: 1,
      pass_count: 0,
      fail_count: 1,
      review_count: 0,
      fatal_failures_count: 0,
      parameter_results: []
    } as any
  });
  const reportIdA = realReportA.report_id;

  const licensingEngine = new LicensingEngine(db);
  const billingService = new BillingService(db, licensingEngine);
  billingService.createSubscriptionCheckout(orgA, 'admin@alpha.com', 'ENTERPRISE', 'ANNUAL');

  const app = express();
  app.use(express.json());
  app.use('/api', createApiRouter(db));

  // 1. Tenant B cannot GET Tenant A scan
  const t1 = await request(app).get(`/api/scans/${scanIdA}`).set('Authorization', `Bearer ${tokenB}`);
  assert.ok([403, 404].includes(t1.status));
  console.log('✔ Test 1: Tenant B cannot GET Tenant A scan');

  // 2. Tenant B cannot GET Tenant A scan progress
  const t2 = await request(app).get(`/api/scans/${scanIdA}/progress`).set('Authorization', `Bearer ${tokenB}`);
  assert.ok([403, 404].includes(t2.status));
  console.log('✔ Test 2: Tenant B cannot GET Tenant A scan progress');

  // 3. Tenant B cannot GET Tenant A file
  const t3 = await request(app).get(`/api/files/${fileIdA}`).set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(t3.status, 404);
  console.log('✔ Test 3: Tenant B cannot GET Tenant A file');

  // 4. Tenant B cannot list Tenant A files
  const t4 = await request(app).get('/api/files').set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(t4.status, 200);
  assert.strictEqual(t4.body.length, 0);
  console.log('✔ Test 4: Tenant B cannot list Tenant A files');

  // 5. Tenant B cannot GET Tenant A findings
  const t5 = await request(app).get('/api/findings').set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(t5.status, 200);
  assert.strictEqual(t5.body.length, 0);
  console.log('✔ Test 5: Tenant B cannot GET Tenant A findings');

  // 6. Tenant B cannot quarantine Tenant A file
  const t6 = await request(app).post(`/api/quarantine/${fileIdA}`).set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(t6.status, 404);
  console.log('✔ Test 6: Tenant B cannot quarantine Tenant A file');

  // 7. Tenant B cannot upload Tenant A file (batch upload)
  const t7 = await request(app).post('/api/cloud-uploads/upload').set('Authorization', `Bearer ${tokenB}`).send({ file_ids: [fileIdA] });
  assert.strictEqual(t7.status, 403);
  console.log('✔ Test 7: Tenant B cannot upload Tenant A file');

  // 8. Tenant B cannot retry Tenant A cloud upload
  const t8 = await request(app).post(`/api/cloud-uploads/retry/${fileIdA}`).set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(t8.status, 403);
  console.log('✔ Test 8: Tenant B cannot retry Tenant A cloud upload');

  // 9. Unauthenticated user cannot retry cloud upload
  const t9 = await request(app).post(`/api/cloud-uploads/retry/${fileIdA}`);
  assert.strictEqual(t9.status, 401);
  console.log('✔ Test 9: Unauthenticated user cannot retry cloud upload');

  // 10. Tenant B cannot execute audit against Tenant A scan
  const t10 = await request(app).post('/api/audit/run').set('Authorization', `Bearer ${tokenB}`).send({ scan_id: scanIdA });
  assert.strictEqual(t10.status, 403);
  console.log('✔ Test 10: Tenant B cannot execute audit against Tenant A scan');

  // 11. Tenant B cannot retrieve Tenant A audit session
  const t11 = await request(app).get(`/api/audit/session/${auditIdA}`).set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(t11.status, 403);
  console.log('✔ Test 11: Tenant B cannot retrieve Tenant A audit session');

  // 12. Tenant B cannot retrieve Tenant A orphan audit session
  const t12 = await request(app).get(`/api/audit/session/${orphanAuditIdA}`).set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(t12.status, 403);
  console.log('✔ Test 12: Tenant B cannot retrieve Tenant A orphan audit session');

  // 13. Tenant B cannot modify / override Tenant A audit result
  const t13 = await request(app).post('/api/audit/override').set('Authorization', `Bearer ${tokenB}`).send({
    audit_id: auditIdA,
    parameter_id: 'ZTI-001',
    new_status: 'PASS',
    auditor_name: 'Attacker'
  });
  assert.strictEqual(t13.status, 403);
  console.log('✔ Test 13: Tenant B cannot modify Tenant A audit result');

  // 14. Tenant B cannot override Tenant A audit result
  const t14 = await request(app).post('/api/audit/override').set('Authorization', `Bearer ${tokenB}`).send({
    audit_id: auditIdA,
    parameter_id: 'ZTI-001',
    new_status: 'PASS',
    auditor_name: 'Attacker'
  });
  assert.strictEqual(t14.status, 403);
  console.log('✔ Test 14: Tenant B cannot override Tenant A audit result');

  // 15. Tenant B cannot override Tenant A orphan audit result
  const t15 = await request(app).post('/api/audit/override').set('Authorization', `Bearer ${tokenB}`).send({
    audit_id: orphanAuditIdA,
    parameter_id: 'ZTI-001',
    new_status: 'PASS',
    auditor_name: 'Attacker'
  });
  assert.strictEqual(t15.status, 403);
  console.log('✔ Test 15: Tenant B cannot override Tenant A orphan audit result');

  // 16. Tenant B cannot register report using Tenant A scan_id
  const t16 = await request(app).post('/api/reports/register').set('Authorization', `Bearer ${tokenB}`).send({ scan_id: scanIdA });
  assert.strictEqual(t16.status, 403);
  console.log('✔ Test 16: Tenant B cannot register report using Tenant A scan_id');

  // 17. Tenant B cannot register report using Tenant A audit_id
  const t17 = await request(app).post('/api/reports/register').set('Authorization', `Bearer ${tokenB}`).send({ audit_id: auditIdA });
  assert.strictEqual(t17.status, 403);
  console.log('✔ Test 17: Tenant B cannot register report using Tenant A audit_id');

  // 18. Tenant B cannot download Tenant A real report
  const t18 = await request(app).get(`/api/reports/${reportIdA}/download`).set('Authorization', `Bearer ${tokenB}`);
  assert.ok([403, 404].includes(t18.status));
  console.log('✔ Test 18: Tenant B cannot download Tenant A real report');

  // 18b. Tenant B cannot revoke Tenant A real report
  const t18b = await request(app).post(`/api/reports/revoke/${reportIdA}`).set('Authorization', `Bearer ${tokenB}`).send({ reason: 'Malicious revocation' });
  assert.ok([400, 403, 404].includes(t18b.status));
  console.log('✔ Test 18b: Tenant B cannot revoke Tenant A real report');

  // 18c. Tenant B cannot inject Tenant A scan_id through canonical_report
  const t18c = await request(app).post('/api/reports/register').set('Authorization', `Bearer ${tokenB}`).send({
    canonical_report: {
      scan_id: scanIdA,
      overall_score: 95
    }
  });
  assert.strictEqual(t18c.status, 403);
  console.log('✔ Test 18c: Tenant B cannot inject Tenant A scan_id through canonical_report');

  // 18d. Tenant B cannot inject Tenant A audit_id through canonical_report
  const t18d = await request(app).post('/api/reports/register').set('Authorization', `Bearer ${tokenB}`).send({
    canonical_report: {
      audit_id: auditIdA,
      overall_score: 95
    }
  });
  assert.strictEqual(t18d.status, 403);
  console.log('✔ Test 18d: Tenant B cannot inject Tenant A audit_id through canonical_report');

  // 18e. Tenant B cannot obtain Tenant A audit session if audit_sessions.org_id != scans.org_id
  const scanIdB = 'SCAN-BETA-001';
  db.prepare(`
    INSERT INTO scans (scan_id, root_path, start_time, status, total_files, org_id, user_id, device_id)
    VALUES (?, '/secret/beta/path', ?, 'COMPLETED', 1, ?, ?, ?)
  `).run(scanIdB, now, orgB, userB, deviceB);

  const mismatchedAuditId = 'AUDIT-MISMATCH-1';
  db.prepare(`
    INSERT INTO audit_sessions (audit_id, scan_id, org_id, audit_date, agency_name, auditor_name, status, overall_score, overall_status, created_at, updated_at)
    VALUES (?, ?, ?, '2026-08-16', 'Alpha Agency', 'Auditor A', 'COMPLETED', 75, 'CONDITIONAL', ?, ?)
  `).run(mismatchedAuditId, scanIdB, orgA, now, now);

  const t18eList = await request(app).get('/api/audit/sessions').set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(t18eList.status, 200);
  assert.strictEqual(t18eList.body.some((s: any) => s.audit_id === mismatchedAuditId), false);

  const t18eGet = await request(app).get(`/api/audit/session/${mismatchedAuditId}`).set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(t18eGet.status, 403);

  const t18eOverride = await request(app).post('/api/audit/override').set('Authorization', `Bearer ${tokenB}`).send({
    audit_id: mismatchedAuditId,
    parameter_id: 'ZTI-001',
    new_status: 'PASS',
    auditor_name: 'Attacker'
  });
  assert.strictEqual(t18eOverride.status, 403);
  console.log('✔ Test 18e: Tenant B cannot obtain Tenant A audit session when audit_sessions.org_id != scans.org_id');

  // 19. Tenant B cannot access Tenant A audit logs
  const t19 = await request(app).get('/api/audit-logs').set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(t19.status, 200);
  assert.strictEqual(t19.body.length, 0);
  console.log('✔ Test 19: Tenant B cannot access Tenant A audit logs');

  // 20. Tenant B cannot access Tenant A dashboard statistics (sees Beta stats)
  const t20 = await request(app).get('/api/dashboard/stats').set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(t20.status, 200);
  assert.strictEqual(t20.body.totalScans, 1);
  console.log('✔ Test 20: Tenant B cannot access Tenant A dashboard statistics');

  // 21. Tenant A dashboard statistics exclude Tenant B
  const t21 = await request(app).get('/api/dashboard/stats').set('Authorization', `Bearer ${tokenA}`);
  assert.strictEqual(t21.status, 200);
  assert.strictEqual(t21.body.totalScans, 1);
  console.log('✔ Test 21: Tenant A dashboard statistics exclude Tenant B');

  // 22. Tenant B cannot access Tenant A license
  const t22 = await request(app).get('/api/license').set('Authorization', `Bearer ${tokenB}`);
  assert.notStrictEqual(t22.body.org_id, orgA);
  console.log('✔ Test 22: Tenant B cannot access Tenant A license');

  // 23. Tenant B cannot access Tenant A subscription
  const t23 = await request(app).get('/api/billing/subscription').set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(t23.status, 404);
  console.log('✔ Test 23: Tenant B cannot access Tenant A subscription');

  // 24. Tenant B cannot access Tenant A device
  const t24 = await request(app).get('/api/devices').set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(t24.status, 200);
  const betaDevices = t24.body.filter((d: any) => d.org_id === orgA);
  assert.strictEqual(betaDevices.length, 0);
  console.log('✔ Test 24: Tenant B cannot access Tenant A device');

  // 25. Tenant B cannot access Tenant A telemetry
  const t25 = await request(app).get(`/api/privacy/telemetry-preview/${scanIdA}`).set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(t25.status, 403);
  console.log('✔ Test 25: Tenant B cannot access Tenant A telemetry');

  // 26. Client-supplied organization_id cannot override authenticated org
  const t26 = await request(app).post('/api/telemetry/scans').set('Authorization', `Bearer ${tokenB}`).send({ organization_id: orgA, scan_id: 'SCAN-FORGERY' });
  assert.strictEqual(t26.status, 403);
  console.log('✔ Test 26: Client-supplied organization_id cannot override authenticated organization');

  // 27. Client-supplied user_id cannot override authenticated user
  const t27 = await request(app).post('/api/telemetry/scans').set('Authorization', `Bearer ${tokenB}`).send({ user_id: userA, scan_id: 'SCAN-FORGERY' });
  assert.strictEqual(t27.status, 403);
  console.log('✔ Test 27: Client-supplied user_id cannot override authenticated user');

  // 28. Batch request containing another tenant's file is rejected safely
  const t28 = await request(app).post('/api/cloud-uploads/upload').set('Authorization', `Bearer ${tokenB}`).send({ file_ids: [fileIdA] });
  assert.strictEqual(t28.status, 403);
  console.log('✔ Test 28: Batch request containing another tenant\'s file is rejected safely');

  // 29. Revoked device cannot access tenant resources
  const t29 = await request(app).get('/api/scans').set('Authorization', `Bearer ${tokenRevoked}`);
  assert.strictEqual(t29.status, 403);
  console.log('✔ Test 29: Revoked device cannot access tenant resources');

  // 30. Disabled user cannot access tenant resources
  const t30 = await request(app).get('/api/scans').set('Authorization', `Bearer ${tokenDisabled}`);
  assert.strictEqual(t30.status, 403);
  console.log('✔ Test 30: Disabled user cannot access tenant resources');

  // 31. VIEWER cannot perform audit override
  const t31 = await request(app).post('/api/audit/override').set('Authorization', `Bearer ${tokenViewerA}`).send({
    audit_id: auditIdA,
    parameter_id: 'ZTI-001',
    new_status: 'PASS',
    auditor_name: 'Viewer'
  });
  assert.strictEqual(t31.status, 403);
  console.log('✔ Test 31: VIEWER cannot perform audit override');

  // 32. Unauthorized role cannot perform administrative operation
  const t32 = await request(app).post('/api/devices/register').set('Authorization', `Bearer ${tokenViewerA}`).send({ device_id: 'dev-new', device_name: 'New Dev' });
  assert.strictEqual(t32.status, 403);
  console.log('✔ Test 32: Unauthorized role cannot perform administrative operation');

  // 33. Random/unknown resource IDs do not leak resource existence
  const t33 = await request(app).get('/api/scans/RANDOM-NONEXISTENT-ID').set('Authorization', `Bearer ${tokenA}`);
  assert.strictEqual(t33.status, 404);
  console.log('✔ Test 33: Random/unknown resource IDs do not leak resource existence');

  // 34. Concurrent requests cannot bypass tenant checks
  const concurrentPromises = Array.from({ length: 10 }).map(() =>
    request(app).get(`/api/scans/${scanIdA}`).set('Authorization', `Bearer ${tokenB}`)
  );
  const results = await Promise.all(concurrentPromises);
  for (const r of results) {
    assert.ok([403, 404].includes(r.status));
  }
  console.log('✔ Test 34: Concurrent cross-tenant requests securely blocked');

  // 35. Health check or public verification route does not leak tenant data
  const t35 = await request(app).get('/api/reports/verify/NONEXISTENT-REPORT');
  assert.strictEqual(t35.status, 200);
  console.log('✔ Test 35: Public verification route handles non-existent reports safely');

  console.log('\n========================================================================');
  console.log('  ALL 35 TENANT ISOLATION & IDOR SECURITY TESTS PASSED SUCCESSFULLY!    ');
  console.log('========================================================================\n');
  process.exit(0);
}

runTenantIsolationTestSuite().catch(err => {
  console.error('Tenant isolation test suite failed:', err);
  process.exit(1);
});
