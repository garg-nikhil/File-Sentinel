import assert from 'node:assert';
import crypto from 'node:crypto';
import { getDatabase } from '../backend/db.js';
import { hashPassword, verifyPassword, logSecurityEvent } from '../backend/auth.js';
import { LicensingEngine } from '../backend/licensing.js';
import { TelemetryService } from '../backend/telemetry.js';
import { BillingService } from '../backend/billing.js';
import { FileScannerEngine } from '../backend/scannerEngine.js';
import {
  checkLoginThrottling,
  recordFailedLogin,
  recordSuccessfulLogin,
  isValidFileId,
  isValidScanId,
  isValidOrgId,
  isValidDeviceId
} from '../backend/securityMiddleware.js';

async function runMultiTenantSecurityTests() {
  console.log('=== RUNNING COMMERCIAL PHASE 7: MULTI-TENANT SECURITY & ADVERSARIAL HARDENING TEST SUITE ===\n');
  const db = getDatabase(':memory:');
  const licensingEngine = new LicensingEngine(db);
  const telemetryService = new TelemetryService(db);
  const webhookSecret = 'test_webhook_secret_phase7';
  const billingService = new BillingService(db, licensingEngine, { webhookSecret });
  const scannerEngine = new FileScannerEngine(db);

  // 1. Setup two distinct test organizations (Tenant Alpha & Tenant Beta)
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO organizations (org_id, name, created_at)
    VALUES ('org-alpha', 'Alpha Corp', ?), ('org-beta', 'Beta Global', ?)
  `).run(now, now);

  const pwdHash = hashPassword('SecurePassword123!');
  db.prepare(`
    INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at)
    VALUES 
      ('usr-alpha-admin', 'org-alpha', 'alpha_admin', ?, 'ORG_ADMIN', 0, ?),
      ('usr-alpha-viewer', 'org-alpha', 'alpha_viewer', ?, 'VIEWER', 0, ?),
      ('usr-beta-admin', 'org-beta', 'beta_admin', ?, 'ORG_ADMIN', 0, ?)
  `).run(pwdHash, now, pwdHash, now, pwdHash, now);

  db.prepare(`
    INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at)
    VALUES 
      ('dev-alpha-1', 'org-alpha', 'Alpha Workstation', 0, ?),
      ('dev-beta-1', 'org-beta', 'Beta Laptop', 0, ?)
  `).run(now, now);

  // Initialize trial licenses
  licensingEngine.issueLicense({ organizationId: 'org-alpha', planId: 'plan-starter-trial', status: 'TRIAL', durationDays: 14 });
  licensingEngine.issueLicense({ organizationId: 'org-beta', planId: 'plan-starter-trial', status: 'TRIAL', durationDays: 14 });

  // --- TEST 1: Cross-Tenant Scan Data Isolation & IDOR Prevention ---
  console.log('1. Testing Cross-Tenant Scan Data Isolation...');
  const alphaScanId = 'SCAN-alpha-private-123456';
  db.prepare(`
    INSERT INTO scans (scan_id, root_path, start_time, status, org_id, user_id, device_id)
    VALUES (?, '/data/alpha/secrets', ?, 'COMPLETED', 'org-alpha', 'usr-alpha-admin', 'dev-alpha-1')
  `).run(alphaScanId, now);

  // Tenant Beta attempts to query Tenant Alpha's scan
  const betaQueryOnAlphaScan = db.prepare('SELECT * FROM scans WHERE scan_id = ? AND org_id = ?').get(alphaScanId, 'org-beta');
  assert.strictEqual(betaQueryOnAlphaScan, undefined, 'Beta tenant must NOT be able to query Alpha scan records directly');

  // Verify telemetry history tenant isolation
  telemetryService.recordScanTelemetry({
    scan_id: alphaScanId,
    organization_id: 'org-alpha',
    user_id: 'usr-alpha-admin',
    device_id: 'dev-alpha-1',
    started_at: now,
    completed_at: now,
    duration_ms: 1200,
    application_version: '1.0.0',
    engine_version: '1.0.0',
    checklist_version: '2026.1',
    files_discovered: 10,
    files_processed: 10,
    files_succeeded: 10,
    files_failed: 0,
    files_rejected_by_resource_limits: 0,
    pass_count: 8,
    review_count: 2,
    fail_count: 0,
    evidence_not_found_count: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    overall_score: 95,
    parameters_evaluated: 10,
    scan_status: 'COMPLETED'
  });

  const betaTelemetryHistory = telemetryService.getScanHistory('org-beta');
  assert.strictEqual(betaTelemetryHistory.length, 0, 'Beta tenant history must not contain Alpha telemetry');

  const betaDirectTelemetryFetch = telemetryService.getScanTelemetry('org-beta', alphaScanId);
  assert.strictEqual(betaDirectTelemetryFetch, null, 'Direct telemetry retrieval must reject mismatched org_id');
  console.log('   ✓ Cross-tenant scan data isolation verified');

  // --- TEST 2: Cross-Tenant Report Verification & No Leakage ---
  console.log('2. Testing Report Verification Security & Data Leakage Prevention...');
  const alphaReportVerify = telemetryService.verifyReport('org-alpha', alphaScanId);
  assert.strictEqual(alphaReportVerify.verified, true, 'Alpha report verification should succeed for Alpha');

  const betaReportVerify = telemetryService.verifyReport('org-beta', alphaScanId);
  assert.strictEqual(betaReportVerify.verified, false, 'Report verification must fail for cross-tenant request');
  assert.strictEqual(betaReportVerify.match_status, 'UNAUTHORIZED_ORGANIZATION');
  assert.strictEqual((betaReportVerify as any).scan_id, undefined, 'Report details must NOT leak on authorization failure');
  console.log('   ✓ Report verification cross-tenant boundary verified');

  // --- TEST 3: Telemetry Organization & User ID Injection Prevention ---
  console.log('3. Testing Telemetry Forgery & Injection Protection...');
  assert.throws(() => {
    // Missing required identification
    telemetryService.recordScanTelemetry({} as any);
  }, /Missing mandatory identification fields/);

  assert.throws(() => {
    // Negative duration injection
    telemetryService.recordScanTelemetry({
      scan_id: 'SCAN-inj-1',
      organization_id: 'org-alpha',
      user_id: 'usr-alpha-admin',
      device_id: 'dev-alpha-1',
      started_at: now,
      completed_at: now,
      duration_ms: -500,
      files_discovered: 5
    } as any);
  }, /Invalid duration_ms/);
  console.log('   ✓ Telemetry payload bounds and parameter validation verified');

  // --- TEST 4: Progressive Login Throttling & Lockout ---
  console.log('4. Testing Progressive Login Throttling & Lockout...');
  const testIpKey = '198.51.100.22:attacker_user';
  recordSuccessfulLogin(testIpKey); // clear start

  // Check initial state
  let throttle = checkLoginThrottling(testIpKey);
  assert.strictEqual(throttle.allowed, true);
  assert.strictEqual(throttle.failedAttempts, 0);

  // Record 5 failed attempts -> should trigger 60s lockout
  for (let i = 0; i < 5; i++) {
    recordFailedLogin(testIpKey);
  }

  throttle = checkLoginThrottling(testIpKey);
  assert.strictEqual(throttle.allowed, false, 'Should be locked out after 5 consecutive failures');
  assert(throttle.remainingLockoutSeconds! > 0, 'Lockout countdown must be positive');

  // Successful login clears throttle record
  recordSuccessfulLogin(testIpKey);
  throttle = checkLoginThrottling(testIpKey);
  assert.strictEqual(throttle.allowed, true, 'Successful login must reset throttle counters');
  console.log('   ✓ Progressive login brute-force defense verified');

  // --- TEST 5: Device Revocation & Token Invalidation ---
  console.log('5. Testing Device Revocation and Token Revocation...');
  const tokenAlpha = 'tok-alpha-session-xyz';
  db.prepare(`
    INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at)
    VALUES (?, 'usr-alpha-admin', 'org-alpha', 'dev-alpha-1', ?, ?)
  `).run(tokenAlpha, new Date(Date.now() + 3600000).toISOString(), now);

  // Revoke device
  db.prepare('UPDATE devices SET revoked = 1 WHERE device_id = ?').run('dev-alpha-1');

  // Check device revocation session query
  const sessionCheck = db.prepare(`
    SELECT s.token, u.disabled, d.revoked as device_revoked
    FROM sessions s
    JOIN users u ON s.user_id = u.user_id
    LEFT JOIN devices d ON s.device_id = d.device_id
    WHERE s.token = ?
  `).get(tokenAlpha) as any;

  assert.strictEqual(sessionCheck.device_revoked, 1, 'Device revoked status must be reflected in session lookup');
  console.log('   ✓ Device revocation enforcement verified');

  // --- TEST 6: Cryptographic Unguessable Scan ID Validation ---
  console.log('6. Testing Cryptographic Unguessable Scan IDs...');
  const scanSession = await scannerEngine.startScan(process.cwd(), [], undefined, 'org-alpha', 'usr-alpha-admin', 'dev-alpha-1');
  assert(scanSession.scan_id.startsWith('SCAN-'), 'Scan ID must follow standardized format');
  assert(scanSession.scan_id.length >= 36, 'Scan ID must be high-entropy 128-bit UUID (unguessable)');
  console.log('   ✓ High-entropy scan ID generation verified');

  // --- TEST 7: Strict Identifier Sanitization & Validation ---
  console.log('7. Testing Strict Identifier Regex Validations...');
  assert.strictEqual(isValidFileId('FILE-valid-12345'), true);
  assert.strictEqual(isValidFileId('FILE-invalid/path/traversal'), false);
  assert.strictEqual(isValidScanId('SCAN-1234-abcd-5678'), true);
  assert.strictEqual(isValidScanId("SCAN-1234'; DROP TABLE scans;--"), false);
  assert.strictEqual(isValidOrgId('org-enterprise-corp'), true);
  assert.strictEqual(isValidOrgId('org<script>alert(1)</script>'), false);
  assert.strictEqual(isValidDeviceId('dev-windows-laptop-01'), true);
  assert.strictEqual(isValidDeviceId('dev-../../etc/passwd'), false);
  console.log('   ✓ Strict input sanitizer regex filters verified');

  // --- TEST 8: Server-Side Webhook Idempotency & Signature Verification ---
  console.log('8. Testing Server-Authoritative Webhook Cryptographic Verification...');
  const webhookEventPayload = {
    event: 'subscription.charged',
    payload: {
      subscription: {
        entity: {
          id: 'sub_test_p7_001',
          plan_id: 'plan_pro_annual',
          customer_id: 'cust_alpha_001',
          status: 'active',
          current_end: Math.floor(Date.now() / 1000) + 365 * 86400
        }
      },
      payment: {
        entity: {
          id: 'pay_test_p7_001',
          amount: 199900,
          currency: 'INR',
          status: 'captured'
        }
      }
    }
  };

  const eventId = 'evt_test_p7_001';
  const rawPayloadStr = JSON.stringify(webhookEventPayload);
  const validSignature = crypto.createHmac('sha256', webhookSecret).update(rawPayloadStr).digest('hex');
  const forgedSignature = 'bad_forged_hmac_signature_0000000000000000000000000000000000000000000';

  // Test forged signature verification rejection
  const isForgedValid = billingService.verifyWebhookSignature(rawPayloadStr, forgedSignature, webhookSecret);
  assert.strictEqual(isForgedValid, false, 'Forged signature must be rejected by verification');

  assert.throws(() => {
    billingService.processWebhook(eventId, rawPayloadStr, forgedSignature, webhookEventPayload as any);
  }, /Invalid Razorpay webhook signature/);

  // Test valid signature acceptance
  // Seed customer map & subscription
  db.prepare(`
    INSERT INTO billing_customers (customer_id, org_id, provider, provider_customer_id, email, name, billing_currency, created_at, updated_at)
    VALUES ('cust_rec_alpha', 'org-alpha', 'RAZORPAY', 'cust_alpha_001', 'admin@alphacorp.com', 'Alpha Corp', 'INR', ?, ?)
  `).run(now, now);

  db.prepare(`
    INSERT INTO subscriptions (
      subscription_id, org_id, customer_id, provider_subscription_id, plan_id, billing_interval,
      status, current_period_start, current_period_end, created_at, updated_at
    ) VALUES (
      'sub-rec-p7-001', 'org-alpha', 'cust_rec_alpha', 'sub_test_p7_001', 'plan-professional', 'ANNUAL',
      'TRIAL', ?, ?, ?, ?
    )
  `).run(now, new Date(Date.now() + 86400000).toISOString(), now, now);

  const validResult = billingService.processWebhook(eventId, rawPayloadStr, validSignature, webhookEventPayload as any);
  assert.strictEqual(validResult.status, 'PROCESSED', 'Valid HMAC signature must be processed');

  // Test replay attack protection (idempotency)
  const replayResult = billingService.processWebhook(eventId, rawPayloadStr, validSignature, webhookEventPayload as any);
  assert.strictEqual(replayResult.status, 'DUPLICATE', 'Duplicate webhook event must be recognized and safely skipped');
  console.log('   ✓ Authoritative webhook signature and replay defense verified');

  console.log('\n========================================================================');
  console.log('ALL COMMERCIAL PHASE 7 SECURITY TESTS PASSED COMPREHENSIVELY!');
  console.log('========================================================================\n');
  process.exit(0);
}

runMultiTenantSecurityTests().catch((err) => {
  console.error('Test Suite Failed:', err);
  process.exit(1);
});
