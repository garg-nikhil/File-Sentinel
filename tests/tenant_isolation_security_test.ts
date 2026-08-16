import { getDatabase } from '../backend/db.js';
import { hashPassword } from '../backend/auth.js';
import { createApiRouter } from '../backend/routes.js';
import assert from 'node:assert';
import express from 'express';
import request from 'supertest';
import crypto from 'node:crypto';

async function runTenantIsolationTestSuite() {
  console.log('========================================================================');
  console.log('  FILE-SENTINEL R8.1: Global Tenant Isolation & IDOR Security Test Suite ');
  console.log('========================================================================\n');

  const db = getDatabase(':memory:');
  const now = new Date().toISOString();

  // Setup two isolated tenants
  const orgA = 'org-tenant-a';
  const orgB = 'org-tenant-b';
  const userA = 'usr-admin-a';
  const userB = 'usr-admin-b';
  const deviceA = 'dev-a';
  const deviceB = 'dev-b';

  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(orgA, 'Tenant Alpha Corp', now);
  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(orgB, 'Tenant Beta Ltd', now);

  db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 0, ?)')
    .run(deviceA, orgA, 'Device A', now);
  db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 0, ?)')
    .run(deviceB, orgB, 'Device B', now);

  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(userA, orgA, 'admin_a', hashPassword('Secret123!'), 'ORG_ADMIN', now);
  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(userB, orgB, 'admin_b', hashPassword('Secret123!'), 'ORG_ADMIN', now);

  // Create test session for Token A and Token B
  const tokenA = 'tok-a-' + crypto.randomBytes(16).toString('hex');
  const tokenB = 'tok-b-' + crypto.randomBytes(16).toString('hex');
  const expiresAt = new Date(Date.now() + 86400000).toISOString();

  db.prepare('INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(tokenA, userA, orgA, deviceA, expiresAt, now);
  db.prepare('INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(tokenB, userB, orgB, deviceB, expiresAt, now);

  // Insert test Scan, File, Finding, Quarantine, Audit Session for Tenant A
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
    INSERT INTO audit_sessions (audit_id, scan_id, audit_date, agency_name, auditor_name, status, overall_score, overall_status, created_at, updated_at)
    VALUES (?, ?, '2026-08-16', 'Alpha Agency', 'Auditor A', 'COMPLETED', 75, 'CONDITIONAL', ?, ?)
  `).run(auditIdA, scanIdA, now, now);

  // Setup express test app
  const app = express();
  app.use(express.json());
  app.use('/api', createApiRouter(db));

  console.log('Test 1: Tenant B trying to access Tenant A scan directly via GET /api/scans/:id...');
  const resScan = await request(app)
    .get(`/api/scans/${scanIdA}`)
    .set('Authorization', `Bearer ${tokenB}`);
  assert.ok([403, 404].includes(resScan.status), 'Tenant B should receive 403 or 404 when attempting to access Tenant A scan');
  console.log('✓ PASSED: Cross-tenant scan access blocked securely');

  console.log('Test 2: Tenant B trying to access Tenant A file directly via GET /api/files/:id...');
  const resFile = await request(app)
    .get(`/api/files/${fileIdA}`)
    .set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(resFile.status, 404, 'Tenant B should receive 404/403 when attempting to access Tenant A file');
  console.log('✓ PASSED: Cross-tenant file access blocked');

  console.log('Test 3: Tenant B requesting GET /api/files should not see Tenant A files...');
  const resFilesList = await request(app)
    .get('/api/files')
    .set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(resFilesList.status, 200);
  assert.strictEqual(resFilesList.body.length, 0, 'Tenant B file list must be empty');
  console.log('✓ PASSED: Tenant file list strictly isolated');

  console.log('Test 4: Tenant B requesting GET /api/findings should not see Tenant A findings...');
  const resFindings = await request(app)
    .get('/api/findings')
    .set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(resFindings.status, 200);
  assert.strictEqual(resFindings.body.length, 0, 'Tenant B findings list must be empty');
  console.log('✓ PASSED: Tenant findings list strictly isolated');

  console.log('Test 5: Tenant B requesting GET /api/quarantine should not see Tenant A quarantine items...');
  const resQuarantine = await request(app)
    .get('/api/quarantine')
    .set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(resQuarantine.status, 200);
  assert.strictEqual(resQuarantine.body.length, 0, 'Tenant B quarantine list must be empty');
  console.log('✓ PASSED: Tenant quarantine items strictly isolated');

  console.log('Test 6: Tenant B trying to access Tenant A audit session via GET /api/audit/session/:id...');
  const resAudit = await request(app)
    .get(`/api/audit/session/${auditIdA}`)
    .set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(resAudit.status, 403, 'Tenant B should receive 403 for Tenant A audit session');
  console.log('✓ PASSED: Cross-tenant audit session access blocked');

  console.log('Test 7: Tenant B trying to batch upload Tenant A file IDs via POST /api/cloud-uploads/upload...');
  const resUpload = await request(app)
    .post('/api/cloud-uploads/upload')
    .set('Authorization', `Bearer ${tokenB}`)
    .send({ file_ids: [fileIdA] });
  assert.strictEqual(resUpload.status, 403, 'Tenant B should receive 403 when attempting to upload Tenant A file');
  console.log('✓ PASSED: Cross-tenant cloud upload attempt blocked');

  console.log('\n========================================================================');
  console.log('  ALL TENANT ISOLATION & IDOR SECURITY TESTS PASSED SUCCESSFULLY!       ');
  console.log('========================================================================\n');
}

runTenantIsolationTestSuite().catch(err => {
  console.error('Tenant isolation test suite failed:', err);
  process.exit(1);
});
