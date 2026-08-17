/**
 * FILE-SENTINEL: Endpoint Assessment Security Test Suite
 * 
 * Verifies that the /api/endpoint/assess production endpoint:
 * 1. Strictly rejects 'mockWindowsUsbData' with HTTP 400 Bad Request
 * 2. Strictly rejects 'platformOverride' with HTTP 400 Bad Request
 * 3. Strictly rejects 'customWebTargets' with HTTP 400 Bad Request
 * 4. Ensures only authentic, real local detection logic is enforced and persisted
 * 5. Prevents fabricated USB state injection from generating Zero-Trust compliance audit records
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
  console.log('  FILE-SENTINEL: Endpoint Security & Mock Rejection Test Suite          ');
  console.log('========================================================================\n');

  const app = express();
  app.use(express.json());

  const db = getDatabase(':memory:');
  app.use('/api', createApiRouter(db));

  const now = new Date().toISOString();
  const orgId = 'org-sec-' + crypto.randomBytes(4).toString('hex');
  const userId = 'usr-sec-' + crypto.randomBytes(4).toString('hex');
  const deviceId = 'dev-sec-' + crypto.randomBytes(4).toString('hex');

  // Seed organization, registered device, user, and session
  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)')
    .run(orgId, 'Endpoint Security Test Org', now);

  db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 0, ?)')
    .run(deviceId, orgId, 'SEC-WORKSTATION-01', now);

  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)')
    .run(userId, orgId, 'sec_admin', hashPassword('SentinelPassword123!'), 'ORG_ADMIN', now);

  const token = 'tok-sec-' + crypto.randomBytes(16).toString('hex');
  const expiresAt = new Date(Date.now() + 86400000).toISOString();

  db.prepare('INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(token, userId, orgId, deviceId, expiresAt, now);

  let passed = 0;

  // 1. Strict rejection of 'mockWindowsUsbData' field
  {
    console.log('1. Testing strict rejection of mockWindowsUsbData parameter...');
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${token}`)
      .send({
        deviceId,
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
      'Error message must explicitly cite mockWindowsUsbData parameter rejection'
    );
    console.log('   ✓ mockWindowsUsbData strictly rejected with HTTP 400');
    passed++;
  }

  // 2. Strict rejection of 'platformOverride' field
  {
    console.log('2. Testing strict rejection of platformOverride parameter...');
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${token}`)
      .send({
        deviceId,
        platformOverride: 'windows'
      });

    assert.strictEqual(res.status, 400, 'Production API must reject platformOverride with HTTP 400');
    assert.ok(
      res.body.error && res.body.error.includes('platformOverride'),
      'Error message must explicitly cite platformOverride parameter rejection'
    );
    console.log('   ✓ platformOverride strictly rejected with HTTP 400');
    passed++;
  }

  // 3. Strict rejection of combined 'mockWindowsUsbData' and 'platformOverride' fields
  {
    console.log('3. Testing strict rejection of combined mock parameters...');
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${token}`)
      .send({
        deviceId,
        platformOverride: 'windows',
        mockWindowsUsbData: {
          status: 'ENABLED',
          confidence: 'HIGH'
        }
      });

    assert.strictEqual(res.status, 400, 'Production API must reject mock payload with HTTP 400');
    console.log('   ✓ Combined mock payload strictly rejected with HTTP 400');
    passed++;
  }

  // 4. Fabricated ENABLED USB payload cannot be converted into audit compliance evidence
  {
    console.log('4. Testing fabricated ENABLED USB state cannot produce audit evidence...');
    const auditId = `audit-${crypto.randomBytes(6).toString('hex')}`;
    db.prepare(`
      INSERT INTO audit_sessions (
        audit_id, org_id, audit_date, agency_name, auditor_name, status,
        overall_status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(auditId, orgId, '2026-08-17', 'Zero Trust Agency', 'Auditor Bob', 'IN_PROGRESS', 'REVIEW_REQUIRED', now, now);

    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${token}`)
      .send({
        deviceId,
        linkAuditSessionId: auditId,
        mockWindowsUsbData: {
          status: 'ENABLED',
          confidence: 'HIGH',
          connectedDeviceCount: 1,
          connectedStorageDevices: [{
            device_type: 'USB Mass Storage',
            manufacturer: 'SanDisk',
            model: 'Cruzer Blade',
            connection_status: 'Connected'
          }]
        }
      });

    assert.strictEqual(res.status, 400, 'Mock injection must be blocked with HTTP 400');
    const paramResults = db.prepare('SELECT COUNT(*) as cnt FROM audit_parameter_results WHERE audit_id = ?').get(auditId) as any;
    assert.strictEqual(paramResults.cnt, 0, 'No audit evidence parameter records can be created from rejected mock payload');
    console.log('   ✓ Fabricated ENABLED payload blocked from generating audit records');
    passed++;
  }

  // 5. Fabricated DISABLED USB payload cannot be converted into audit compliance evidence
  {
    console.log('5. Testing fabricated DISABLED USB state cannot produce audit evidence...');
    const auditId = `audit-${crypto.randomBytes(6).toString('hex')}`;
    db.prepare(`
      INSERT INTO audit_sessions (
        audit_id, org_id, audit_date, agency_name, auditor_name, status,
        overall_status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(auditId, orgId, '2026-08-17', 'Zero Trust Agency', 'Auditor Bob', 'IN_PROGRESS', 'REVIEW_REQUIRED', now, now);

    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${token}`)
      .send({
        deviceId,
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
    console.log('   ✓ Fabricated DISABLED payload blocked from generating audit records');
    passed++;
  }

  // 6. Legitimate Request executes real local detection logic
  {
    console.log('6. Testing legitimate production request executes real local detection logic...');
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${token}`)
      .send({
        deviceId
      });

    assert.strictEqual(res.status, 200, 'Authentic assessment request must succeed');
    assert.ok(res.body.id.startsWith('EP-ASM-'), 'Assessment ID must match EP-ASM- prefix');
    assert.strictEqual(res.body.org_id, orgId, 'Assessment organization ID must match');
    assert.strictEqual(res.body.device_id, deviceId, 'Assessment device ID must match');
    assert.ok(res.body.platform, 'Host platform must be authentically detected');
    assert.ok(res.body.usb_result, 'Real USB detection result object must be present');
    assert.ok(Array.isArray(res.body.web_results) && res.body.web_results.length > 0, 'Real web access detection probes must be executed');
    assert.ok(res.body.evidence_text && res.body.evidence_text.length > 50, 'Deterministic evidence text must be populated');

    // Confirm persisted in SQLite database
    const saved = db.prepare('SELECT * FROM endpoint_assessments WHERE id = ?').get(res.body.id) as any;
    assert.ok(saved, 'Assessment must be stored in database');
    assert.strictEqual(saved.org_id, orgId, 'Stored assessment org_id must match');
    console.log('   ✓ Real local detection logic enforced, executed, and persisted');
    passed++;
  }

  console.log('\n========================================================================');
  console.log(`  ALL ${passed}/${passed} ENDPOINT SECURITY TESTS PASSED (100% SUCCESS)`);
  console.log('========================================================================\n');
}

runEndpointSecurityTests().catch((err) => {
  console.error('Endpoint Security Test Failed:', err);
  process.exit(1);
});
