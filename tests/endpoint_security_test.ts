/**
 * FILE-SENTINEL: Endpoint Assessment Security Test Suite
 * 
 * Verifies that the /api/endpoint/assess production endpoint:
 * 1. Request without body deviceId -> uses authenticated device ID from session
 * 2. Request with body deviceId -> HTTP 400 Bad Request
 * 3. Authenticated device A cannot cause an assessment on the local machine to be recorded as device B
 * 4. Missing authenticated device identity -> HTTP 400 DEVICE_IDENTITY_UNAVAILABLE
 * 5. Cross-tenant device -> HTTP 403 Forbidden
 * 6. Revoked device -> HTTP 403 Forbidden
 * 7. Strictly rejects 'mockWindowsUsbData' with HTTP 400 Bad Request
 * 8. Strictly rejects 'platformOverride' with HTTP 400 Bad Request
 * 9. Fabricated mock states cannot generate Zero-Trust compliance audit records
 * 10. Authentic assessment request executes real local detection logic and records session device identity
 */

import assert from 'node:assert';
import request from 'supertest';
import express from 'express';
import crypto from 'node:crypto';
import { getDatabase } from '../backend/db.js';
import { hashPassword } from '../backend/auth.js';
import { createApiRouter } from '../backend/routes.js';

async function runEndpointSecurityTests() {
  console.log('\n========================================================================');
  console.log('  FILE-SENTINEL: Endpoint Security & Device Identity Test Suite         ');
  console.log('========================================================================\n');

  const app = express();
  app.use(express.json());

  const db = getDatabase(':memory:');
  app.use('/api', createApiRouter(db));

  const now = new Date().toISOString();
  const orgA = 'org-sec-a-' + crypto.randomBytes(4).toString('hex');
  const orgB = 'org-sec-b-' + crypto.randomBytes(4).toString('hex');
  const userA = 'usr-sec-a-' + crypto.randomBytes(4).toString('hex');
  const deviceA = 'dev-sec-a-' + crypto.randomBytes(4).toString('hex');
  const deviceB = 'dev-sec-b-' + crypto.randomBytes(4).toString('hex');
  const deviceRevoked = 'dev-sec-rev-' + crypto.randomBytes(4).toString('hex');

  // Seed organizations
  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)')
    .run(orgA, 'Endpoint Security Test Org A', now);
  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)')
    .run(orgB, 'Endpoint Security Test Org B', now);

  // Seed devices
  db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 0, ?)')
    .run(deviceA, orgA, 'SEC-WORKSTATION-A', now);
  db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 0, ?)')
    .run(deviceB, orgB, 'SEC-WORKSTATION-B', now);
  db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 1, ?)')
    .run(deviceRevoked, orgA, 'SEC-WORKSTATION-REVOKED', now);

  // Seed user
  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)')
    .run(userA, orgA, 'sec_admin_a', hashPassword('SentinelPassword123!'), 'ORG_ADMIN', now);

  const expiresAt = new Date(Date.now() + 86400000).toISOString();

  // Valid session with deviceA
  const tokenValid = 'tok-sec-val-' + crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(tokenValid, userA, orgA, deviceA, expiresAt, now);

  // Session without device_id
  const tokenNoDevice = 'tok-sec-nodev-' + crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, NULL, ?, ?)')
    .run(tokenNoDevice, userA, orgA, expiresAt, now);

  // Session with cross-tenant deviceB
  const tokenCrossTenantDevice = 'tok-sec-crossdev-' + crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(tokenCrossTenantDevice, userA, orgA, deviceB, expiresAt, now);

  // Session with revoked device
  const tokenRevokedDevice = 'tok-sec-revdev-' + crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(tokenRevokedDevice, userA, orgA, deviceRevoked, expiresAt, now);

  let passed = 0;

  // 1. Request without body deviceId -> uses authenticated device ID
  {
    console.log('1. Testing request without body deviceId uses authenticated device ID...');
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenValid}`)
      .send({});

    assert.strictEqual(res.status, 200, 'Assessment request without body deviceId must succeed');
    assert.strictEqual(res.body.device_id, deviceA, 'Assessment must record authenticated session device ID');
    console.log('   ✓ Request without body deviceId successfully bound to session device ID');
    passed++;
  }

  // 2. Request with body deviceId -> strictly rejected with HTTP 400
  {
    console.log('2. Testing request with body deviceId is strictly rejected with HTTP 400...');
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenValid}`)
      .send({
        deviceId: deviceA
      });

    assert.strictEqual(res.status, 400, 'Production API must reject body deviceId with HTTP 400');
    assert.ok(
      res.body.error && res.body.error.includes('deviceId'),
      'Error must explain that deviceId is not permitted in request body'
    );
    console.log('   ✓ Request with body deviceId strictly rejected with HTTP 400');
    passed++;
  }

  // 3. Authenticated device A cannot cause an assessment on the local machine to be recorded as device B
  {
    console.log('3. Testing client cannot spoof physical endpoint identity as device B...');
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenValid}`)
      .send({
        deviceId: deviceB
      });

    assert.strictEqual(res.status, 400, 'Spoofed deviceId attempt must be rejected with HTTP 400');
    console.log('   ✓ Attempt to label physical endpoint as device B blocked with HTTP 400');
    passed++;
  }

  // 4. Missing authenticated device identity -> HTTP 400 DEVICE_IDENTITY_UNAVAILABLE
  {
    console.log('4. Testing missing authenticated device identity returns HTTP 400 DEVICE_IDENTITY_UNAVAILABLE...');
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenNoDevice}`)
      .send({});

    assert.strictEqual(res.status, 400, 'Missing session deviceId must return HTTP 400');
    assert.ok(
      res.body.error && res.body.error.includes('DEVICE_IDENTITY_UNAVAILABLE'),
      'Error message must contain DEVICE_IDENTITY_UNAVAILABLE'
    );
    console.log('   ✓ Missing session device identity returned HTTP 400 DEVICE_IDENTITY_UNAVAILABLE');
    passed++;
  }

  // 5. Cross-tenant device -> HTTP 403 Forbidden
  {
    console.log('5. Testing session with cross-tenant device returns HTTP 403 Forbidden...');
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenCrossTenantDevice}`)
      .send({});

    assert.strictEqual(res.status, 403, 'Cross-tenant device in session must be rejected with HTTP 403');
    console.log('   ✓ Cross-tenant device rejected with HTTP 403');
    passed++;
  }

  // 6. Revoked device -> HTTP 403 Forbidden
  {
    console.log('6. Testing session with revoked device returns HTTP 403 Forbidden...');
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenRevokedDevice}`)
      .send({});

    assert.strictEqual(res.status, 403, 'Revoked device in session must be rejected with HTTP 403');
    console.log('   ✓ Revoked device rejected with HTTP 403');
    passed++;
  }

  // 7. Strict rejection of 'mockWindowsUsbData' parameter
  {
    console.log('7. Testing strict rejection of mockWindowsUsbData parameter...');
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenValid}`)
      .send({
        mockWindowsUsbData: {
          status: 'DISABLED',
          confidence: 'HIGH',
          connectedDeviceCount: 0,
          connectedStorageDevices: []
        }
      });

    assert.strictEqual(res.status, 400, 'Production API must reject mockWindowsUsbData with HTTP 400');
    assert.ok(
      res.body.error && res.body.error.includes('mockWindowsUsbData'),
      'Error message must cite mockWindowsUsbData rejection'
    );
    console.log('   ✓ mockWindowsUsbData strictly rejected with HTTP 400');
    passed++;
  }

  // 8. Strict rejection of 'platformOverride' parameter
  {
    console.log('8. Testing strict rejection of platformOverride parameter...');
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenValid}`)
      .send({
        platformOverride: 'windows'
      });

    assert.strictEqual(res.status, 400, 'Production API must reject platformOverride with HTTP 400');
    assert.ok(
      res.body.error && res.body.error.includes('platformOverride'),
      'Error message must cite platformOverride rejection'
    );
    console.log('   ✓ platformOverride strictly rejected with HTTP 400');
    passed++;
  }

  // 9. Fabricated USB state injection cannot create audit evidence
  {
    console.log('9. Testing fabricated USB state cannot produce audit compliance evidence...');
    const auditId = `audit-${crypto.randomBytes(6).toString('hex')}`;
    db.prepare(`
      INSERT INTO audit_sessions (
        audit_id, org_id, audit_date, agency_name, auditor_name, status,
        overall_status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(auditId, orgA, '2026-08-17', 'Zero Trust Agency', 'Auditor Bob', 'IN_PROGRESS', 'REVIEW_REQUIRED', now, now);

    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenValid}`)
      .send({
        linkAuditSessionId: auditId,
        mockWindowsUsbData: {
          status: 'DISABLED',
          confidence: 'HIGH',
          connectedDeviceCount: 0,
          connectedStorageDevices: []
        }
      });

    assert.strictEqual(res.status, 400, 'Mock injection must be blocked with HTTP 400');
    const paramResults = db.prepare('SELECT COUNT(*) as cnt FROM audit_parameter_results WHERE audit_id = ?').get(auditId) as any;
    assert.strictEqual(paramResults.cnt, 0, 'No audit evidence parameter records can be created from rejected mock payload');
    console.log('   ✓ Fabricated payload blocked from generating audit records');
    passed++;
  }

  // 10. Authentic assessment request executes real local detection logic
  {
    console.log('10. Testing authentic assessment request executes real local detection logic...');
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${tokenValid}`)
      .send({});

    assert.strictEqual(res.status, 200, 'Authentic assessment request must succeed');
    assert.ok(res.body.id.startsWith('EP-ASM-'), 'Assessment ID must match EP-ASM- prefix');
    assert.strictEqual(res.body.org_id, orgA, 'Assessment organization ID must match');
    assert.strictEqual(res.body.device_id, deviceA, 'Assessment device ID must match session device ID');
    assert.ok(res.body.platform, 'Host platform must be authentically detected');
    assert.ok(res.body.usb_result, 'Real USB detection result object must be present');
    assert.ok(Array.isArray(res.body.web_results) && res.body.web_results.length > 0, 'Real web access detection probes must be executed');
    assert.ok(res.body.evidence_text && res.body.evidence_text.length > 50, 'Deterministic evidence text must be populated');

    // Confirm persisted in SQLite database
    const saved = db.prepare('SELECT * FROM endpoint_assessments WHERE id = ?').get(res.body.id) as any;
    assert.ok(saved, 'Assessment must be stored in database');
    assert.strictEqual(saved.org_id, orgA, 'Stored assessment org_id must match');
    assert.strictEqual(saved.device_id, deviceA, 'Stored assessment device_id must match');
    console.log('   ✓ Real local detection logic enforced, executed, and persisted');
    passed++;
  }

  console.log('\n========================================================================');
  console.log(`  ALL ${passed}/${passed} ENDPOINT SECURITY TESTS PASSED (100% SUCCESS)`);
  console.log('========================================================================\n');
  process.exit(0);
}

runEndpointSecurityTests().catch((err) => {
  console.error('Endpoint Security Test Failed:', err);
  process.exit(1);
});
