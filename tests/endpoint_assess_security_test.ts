/**
 * FILE-SENTINEL: Endpoint Assessment Security Unit Tests
 * 
 * Specifically verifies that the /api/endpoint/assess production endpoint:
 * 1. Rejects mockWindowsUsbData fields with HTTP 400 Bad Request
 * 2. Rejects platformOverride fields with HTTP 400 Bad Request
 * 3. Rejects customWebTargets with HTTP 400 Bad Request
 * 4. Ensures only real local detection is performed
 * 5. Prevents fabricated USB states (DISABLED / ENABLED) from producing audit evidence records
 */

import assert from 'node:assert';
import request from 'supertest';
import express from 'express';
import crypto from 'node:crypto';
import { getDatabase } from '../backend/db.js';
import { hashPassword } from '../backend/auth.js';
import { createApiRouter } from '../backend/routes.js';
import { BillingService } from '../backend/billing.js';
import { LicensingEngine } from '../backend/licensing.js';
import { VerifiableAuditReportService } from '../backend/audit/verifiableReportService.js';

async function runEndpointSecurityUnitTests() {
  console.log('\n========================================================================');
  console.log('  FILE-SENTINEL: /api/endpoint/assess Production Security Unit Tests    ');
  console.log('========================================================================\n');

  const app = express();
  app.use(express.json());

  const db = getDatabase(':memory:');
  app.use('/api', createApiRouter(db));

  const now = new Date().toISOString();
  const orgId = 'org-sec-test-' + crypto.randomBytes(4).toString('hex');
  const userId = 'usr-admin-' + crypto.randomBytes(4).toString('hex');
  const deviceId = 'dev-sec-' + crypto.randomBytes(4).toString('hex');

  // Seed org, device, user, and session
  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)')
    .run(orgId, 'Security Test Corp', now);

  db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 0, ?)')
    .run(deviceId, orgId, 'SEC-HOST-01', now);

  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)')
    .run(userId, orgId, 'sec_admin', hashPassword('Secret123!'), 'ORG_ADMIN', now);

  const token = 'tok-sec-' + crypto.randomBytes(16).toString('hex');
  const expiresAt = new Date(Date.now() + 86400000).toISOString();

  db.prepare('INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(token, userId, orgId, deviceId, expiresAt, now);

  let passed = 0;

  // 1. Rejection of mockWindowsUsbData
  {
    console.log('1. Testing rejection of mockWindowsUsbData...');
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

    assert.strictEqual(res.status, 400, 'Must return HTTP 400 when mockWindowsUsbData is passed');
    assert.ok(
      res.body.error && res.body.error.includes('mockWindowsUsbData'),
      'Error message must explicitly note mockWindowsUsbData rejection'
    );
    console.log('   ✓ mockWindowsUsbData safely rejected with HTTP 400');
    passed++;
  }

  // 2. Rejection of platformOverride
  {
    console.log('2. Testing rejection of platformOverride...');
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${token}`)
      .send({
        deviceId,
        platformOverride: 'windows'
      });

    assert.strictEqual(res.status, 400, 'Must return HTTP 400 when platformOverride is passed');
    assert.ok(
      res.body.error && res.body.error.includes('platformOverride'),
      'Error message must explicitly note platformOverride rejection'
    );
    console.log('   ✓ platformOverride safely rejected with HTTP 400');
    passed++;
  }

  // 3. Rejection of customWebTargets
  {
    console.log('3. Testing rejection of customWebTargets...');
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${token}`)
      .send({
        deviceId,
        customWebTargets: [{ service_name: 'Test', primary_domain: 'test.com' }]
      });

    assert.strictEqual(res.status, 400, 'Must return HTTP 400 when customWebTargets is passed');
    assert.ok(
      res.body.error && res.body.error.includes('customWebTargets'),
      'Error message must explicitly note customWebTargets rejection'
    );
    console.log('   ✓ customWebTargets safely rejected with HTTP 400');
    passed++;
  }

  // 4. Fabricated ENABLED USB payload cannot inject compliance evidence
  {
    console.log('4. Testing fabricated ENABLED USB injection prevention...');
    const auditId = `audit-${crypto.randomBytes(6).toString('hex')}`;
    db.prepare(`
      INSERT INTO audit_sessions (
        audit_id, org_id, audit_date, agency_name, auditor_name, status,
        overall_status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(auditId, orgId, '2026-08-17', 'Test Agency', 'Auditor Alice', 'IN_PROGRESS', 'REVIEW_REQUIRED', now, now);

    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${token}`)
      .send({
        deviceId,
        linkAuditSessionId: auditId,
        mockWindowsUsbData: {
          status: 'ENABLED',
          confidence: 'HIGH'
        }
      });

    assert.strictEqual(res.status, 400, 'Fabricated payload request must fail');
    const paramResults = db.prepare('SELECT COUNT(*) as cnt FROM audit_parameter_results WHERE audit_id = ?').get(auditId) as any;
    assert.strictEqual(paramResults.cnt, 0, 'No audit evidence parameter results may be created from rejected request');
    console.log('   ✓ Fabricated ENABLED payload blocked from producing compliance evidence');
    passed++;
  }

  // 5. Fabricated DISABLED USB payload cannot inject compliance evidence
  {
    console.log('5. Testing fabricated DISABLED USB injection prevention...');
    const auditId = `audit-${crypto.randomBytes(6).toString('hex')}`;
    db.prepare(`
      INSERT INTO audit_sessions (
        audit_id, org_id, audit_date, agency_name, auditor_name, status,
        overall_status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(auditId, orgId, '2026-08-17', 'Test Agency', 'Auditor Alice', 'IN_PROGRESS', 'REVIEW_REQUIRED', now, now);

    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${token}`)
      .send({
        deviceId,
        linkAuditSessionId: auditId,
        mockWindowsUsbData: {
          status: 'DISABLED',
          confidence: 'HIGH'
        }
      });

    assert.strictEqual(res.status, 400, 'Fabricated payload request must fail');
    const paramResults = db.prepare('SELECT COUNT(*) as cnt FROM audit_parameter_results WHERE audit_id = ?').get(auditId) as any;
    assert.strictEqual(paramResults.cnt, 0, 'No audit evidence parameter results may be created from rejected request');
    console.log('   ✓ Fabricated DISABLED payload blocked from producing compliance evidence');
    passed++;
  }

  // 6. Legitimate Request executes real local detection
  {
    console.log('6. Testing legitimate assessment request executes real local detection...');
    const res = await request(app)
      .post('/api/endpoint/assess')
      .set('Authorization', `Bearer ${token}`)
      .send({
        deviceId
      });

    assert.strictEqual(res.status, 200, 'Legitimate assessment must succeed');
    assert.ok(res.body.id.startsWith('EP-ASM-'), 'Assessment ID must be generated');
    assert.strictEqual(res.body.org_id, orgId);
    assert.strictEqual(res.body.device_id, deviceId);
    assert.ok(res.body.usb_result, 'Real USB detection result must be present');
    assert.ok(res.body.web_results && Array.isArray(res.body.web_results), 'Real Web detection results must be present');
    assert.ok(res.body.evidence_text && res.body.evidence_text.length > 50, 'Deterministic evidence text must be populated');

    // Confirm stored in SQLite
    const saved = db.prepare('SELECT * FROM endpoint_assessments WHERE id = ?').get(res.body.id) as any;
    assert.ok(saved, 'Assessment must be saved in database');
    assert.strictEqual(saved.org_id, orgId);
    console.log('   ✓ Real local detection executed and assessment successfully recorded');
    passed++;
  }

  console.log('\n========================================================================');
  console.log(`  ALL ${passed}/${passed} ENDPOINT SECURITY TESTS PASSED (100% SUCCESS)`);
  console.log('========================================================================\n');
  process.exit(0);
}

runEndpointSecurityUnitTests().catch((err) => {
  console.error('Security Unit Test Failed:', err);
  process.exit(1);
});
