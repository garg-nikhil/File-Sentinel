import { getDatabase } from '../backend/db.js';
import { LicensingEngine } from '../backend/licensing.js';
import assert from 'node:assert';
import express from 'express';
import request from 'supertest';
import { createApiRouter } from '../backend/routes.js';

async function runPhase2LicensingTests() {
  console.log('================================================================');
  console.log('   FileSentinel Commercialization Phase 2: Licensing Engine Test ');
  console.log('================================================================');

  const db = getDatabase(':memory:');
  const engine = new LicensingEngine(db, 72);

  // Test 1: Plans seeded and accessible
  const plans = db.prepare('SELECT * FROM plans').all() as any[];
  assert.ok(plans.length >= 3, 'Default plans (Trial, Pro, Enterprise) seeded');
  const enterprisePlan = plans.find(p => p.plan_id === 'plan-enterprise');
  assert.ok(enterprisePlan, 'Enterprise plan exists');
  assert.strictEqual(enterprisePlan.scan_limit, -1, 'Enterprise plan has unlimited scan quota');
  console.log('  ✔ [TEST 1] Subscription plans schema and seeding verified.');

  // Test 2: Default development organization license
  const defaultLic = engine.getLicenseForOrg('org-default-dev');
  assert.ok(defaultLic, 'Default dev organization license exists');
  assert.strictEqual(defaultLic.status, 'ACTIVE', 'Default license is ACTIVE');
  assert.ok(defaultLic.feature_flags.includes('LOCAL_SCANNING'), 'Has LOCAL_SCANNING feature');

  const validation = engine.validateLicense('org-default-dev', { deviceId: 'dev-device-default' });
  assert.strictEqual(validation.valid, true, 'Default license validates successfully');
  assert.strictEqual(validation.ui_state, 'ACTIVE', 'UI state is ACTIVE');
  console.log('  ✔ [TEST 2] Server-authoritative license validation verified.');

  // Test 3: Admin API: Issue a Trial license with 2 device limit and 2 scan limit
  const app = express();
  app.use(express.json());
  app.use('/api', createApiRouter(db));

  // First create a new test organization
  const orgTestId = 'org-test-trial';
  const now = new Date().toISOString();
  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(orgTestId, 'Test Trial Org', now);

  const sysLogin = await request(app)
    .post('/api/auth/login')
    .send({ username: 'sysadmin', password: 'SysAdmin123!' });
  const sysToken = sysLogin.body.token;

  const issueRes = await request(app)
    .post('/api/admin/licenses/issue')
    .set('Authorization', `Bearer ${sysToken}`)
    .send({
      organization_id: orgTestId,
      plan_id: 'plan-starter-trial',
      status: 'TRIAL',
      duration_days: 14,
      max_devices: 2,
      scan_limit: 2,
      feature_flags: ['LOCAL_SCANNING', 'AUDIT_ENGINE']
    });

  assert.strictEqual(issueRes.status, 200, 'Admin license issuance succeeds');
  const trialLicense = db.prepare('SELECT * FROM licenses WHERE organization_id = ?').get(orgTestId) as any;
  assert.strictEqual(trialLicense.status, 'TRIAL');
  assert.strictEqual(trialLicense.max_devices, 2);
  assert.strictEqual(trialLicense.scan_limit, 2);
  console.log('  ✔ [TEST 3] Admin API license issuance verified.');

  // Test 4: Device activation and device limit enforcement
  // Register 3 devices under orgTestId
  db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 0, ?)')
    .run('dev-trial-1', orgTestId, 'Trial Laptop 1', now);
  db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 0, ?)')
    .run('dev-trial-2', orgTestId, 'Trial Laptop 2', now);
  db.prepare('INSERT INTO devices (device_id, org_id, device_name, revoked, registered_at) VALUES (?, ?, ?, 0, ?)')
    .run('dev-trial-3', orgTestId, 'Trial Laptop 3', now);

  // Activate device 1 & 2
  const act1 = engine.activateDevice(trialLicense.license_id, orgTestId, 'dev-trial-1');
  assert.strictEqual(act1.success, true, 'Device 1 activated');
  const act2 = engine.activateDevice(trialLicense.license_id, orgTestId, 'dev-trial-2');
  assert.strictEqual(act2.success, true, 'Device 2 activated');

  // Attempt activating device 3 (should fail due to max_devices: 2)
  const act3 = engine.activateDevice(trialLicense.license_id, orgTestId, 'dev-trial-3');
  assert.strictEqual(act3.success, false, 'Device 3 activation rejected due to limit');
  assert.ok(act3.message?.includes('Maximum device limit reached'), 'Clear error message returned');

  // Deactivate device 1 and re-activate device 3
  const deact1 = engine.deactivateDevice(trialLicense.license_id, orgTestId, 'dev-trial-1');
  assert.strictEqual(deact1.success, true, 'Device 1 deactivated');
  const act3Retry = engine.activateDevice(trialLicense.license_id, orgTestId, 'dev-trial-3');
  assert.strictEqual(act3Retry.success, true, 'Device 3 activated after slot freed');
  console.log('  ✔ [TEST 4] Device allocation, activation limits, and slot freeing verified.');

  // Test 5: Scan quota enforcement
  const scanVal1 = engine.validateLicense(orgTestId, { deviceId: 'dev-trial-2', isStartingScan: true });
  assert.strictEqual(scanVal1.valid, true, 'Scan 1 allowed');
  engine.consumeScanQuota(trialLicense.license_id, 1);

  const scanVal2 = engine.validateLicense(orgTestId, { deviceId: 'dev-trial-2', isStartingScan: true });
  assert.strictEqual(scanVal2.valid, true, 'Scan 2 allowed');
  engine.consumeScanQuota(trialLicense.license_id, 1);

  // Scan 3 should be rejected as quota is exhausted
  const scanVal3 = engine.validateLicense(orgTestId, { deviceId: 'dev-trial-2', isStartingScan: true });
  assert.strictEqual(scanVal3.valid, false, 'Scan 3 rejected when quota exhausted');
  assert.strictEqual(scanVal3.ui_state, 'SCAN_LIMIT_REACHED');
  console.log('  ✔ [TEST 5] Scan quota limit and consumption tracking verified.');

  // Test 6: Feature entitlement validation (e.g. MULTI_FOLDER_SCAN not in starter plan)
  const multiCheck = engine.validateLicense(orgTestId, {
    deviceId: 'dev-trial-2',
    requiredFeature: 'MULTI_FOLDER_SCAN'
  });
  assert.strictEqual(multiCheck.valid, false, 'MULTI_FOLDER_SCAN feature disallowed on trial');
  assert.ok(multiCheck.error?.includes('MULTI_FOLDER_SCAN'), 'Error mentions missing feature');

  const localScanCheck = engine.validateLicense(orgTestId, {
    deviceId: 'dev-trial-2',
    requiredFeature: 'LOCAL_SCANNING'
  });
  assert.strictEqual(localScanCheck.valid, true, 'LOCAL_SCANNING feature allowed on trial');
  console.log('  ✔ [TEST 6] Feature entitlement matrix gating verified.');

  // Test 7: Expiration and Grace Period transition
  const orgGraceId = 'org-test-grace';
  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(orgGraceId, 'Grace Org', now);

  const yesterday = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const nextWeek = new Date(Date.now() + 6 * 24 * 3600 * 1000).toISOString();

  // Create an expired license that is within grace period
  const graceLicId = 'lic-grace-test';
  db.prepare(`
    INSERT INTO licenses (
      license_id, organization_id, plan_id, status, issued_at, starts_at, expires_at,
      grace_until, max_users, max_devices, scan_limit, scans_used, feature_flags,
      created_at, updated_at, last_validated_at
    ) VALUES (?, ?, 'plan-professional', 'ACTIVE', ?, ?, ?, ?, 10, 10, 100, 0, ?, ?, ?, ?)
  `).run(
    graceLicId,
    orgGraceId,
    yesterday,
    yesterday,
    yesterday,
    nextWeek,
    JSON.stringify(['LOCAL_SCANNING']),
    yesterday,
    yesterday,
    yesterday
  );

  const graceVal = engine.validateLicense(orgGraceId);
  assert.strictEqual(graceVal.valid, true, 'License is valid during grace period');
  assert.strictEqual(graceVal.ui_state, 'OFFLINE_GRACE', 'UI state reflects OFFLINE_GRACE');
  assert.strictEqual(graceVal.grace_active, true, 'grace_active flag is true');

  // Verify status was transitioned to GRACE_PERIOD in DB
  const updatedGraceLic = engine.getLicenseForOrg(orgGraceId);
  assert.strictEqual(updatedGraceLic?.status, 'GRACE_PERIOD', 'Database status transitioned to GRACE_PERIOD');
  console.log('  ✔ [TEST 7] Automatic grace period transition verified.');

  // Test 8: Full expiration beyond grace window
  const orgExpiredId = 'org-test-expired';
  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(orgExpiredId, 'Expired Org', now);
  const twoWeeksAgo = new Date(Date.now() - 14 * 24 * 3600 * 1000).toISOString();

  db.prepare(`
    INSERT INTO licenses (
      license_id, organization_id, plan_id, status, issued_at, starts_at, expires_at,
      grace_until, max_users, max_devices, scan_limit, scans_used, feature_flags,
      created_at, updated_at, last_validated_at
    ) VALUES (?, ?, 'plan-professional', 'ACTIVE', ?, ?, ?, ?, 10, 10, 100, 0, ?, ?, ?, ?)
  `).run(
    'lic-expired-test',
    orgExpiredId,
    twoWeeksAgo,
    twoWeeksAgo,
    yesterday,
    yesterday,
    JSON.stringify(['LOCAL_SCANNING']),
    twoWeeksAgo,
    twoWeeksAgo,
    twoWeeksAgo
  );

  const expiredVal = engine.validateLicense(orgExpiredId);
  assert.strictEqual(expiredVal.valid, false, 'Expired license is invalid');
  assert.strictEqual(expiredVal.ui_state, 'EXPIRED', 'UI state is EXPIRED');
  assert.strictEqual(expiredVal.status, 'EXPIRED');
  console.log('  ✔ [TEST 8] Expired license rejection verified.');

  // Test 9: Extension of license via Admin API
  const extendRes = await request(app)
    .post(`/api/admin/licenses/lic-expired-test/extend`)
    .set('Authorization', `Bearer ${sysToken}`)
    .send({ additional_days: 30 });
  assert.strictEqual(extendRes.status, 200, 'Extension succeeded');
  assert.ok(extendRes.body.new_expires_at, 'New expiration date returned');

  const revalidated = engine.validateLicense(orgExpiredId);
  assert.strictEqual(revalidated.valid, true, 'License becomes valid after extension');
  assert.strictEqual(revalidated.status, 'ACTIVE');
  console.log('  ✔ [TEST 9] License extension and re-activation verified.');

  // Test 10: Clock manipulation detection event
  const clockTamperClientTime = new Date(Date.now() - 3600 * 1000).toISOString(); // 1 hour behind
  engine.validateLicense(orgExpiredId, { clientReportedTime: clockTamperClientTime });
  const clockEvents = db.prepare("SELECT * FROM license_events WHERE event_type = 'CLOCK_SKEW_DETECTED'").all();
  assert.ok(clockEvents.length > 0, 'Clock skew event captured in audit log');
  console.log('  ✔ [TEST 10] Clock skew / manipulation detection verified.');

  // Test 11: Protected Customer API for License and Devices
  // Create user in orgGraceId
  const salt = 'testsalt';
  const hash = 'testhash';
  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)')
    .run('user-grace-admin', orgGraceId, 'graceadmin', `${salt}:${hash}`, 'ORG_ADMIN', now);
  db.prepare('INSERT INTO sessions (token, user_id, org_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run('token-grace-admin', 'user-grace-admin', orgGraceId, 'dev-grace-1', nextWeek, now);

  const getLicRes = await request(app)
    .get('/api/license')
    .set('Authorization', 'Bearer token-grace-admin');
  assert.strictEqual(getLicRes.status, 200);
  assert.strictEqual(getLicRes.body.valid, true);
  assert.strictEqual(getLicRes.body.organization_id, orgGraceId);
  console.log('  ✔ [TEST 11] Customer /api/license endpoint verified.');

  console.log('\n================================================================');
  console.log('   ALL PHASE 2 LICENSING TESTS PASSED PERFECTLY (11/11)!        ');
  console.log('================================================================\n');
  process.exit(0);
}

runPhase2LicensingTests().catch(err => {
  console.error('Phase 2 Licensing test failed:', err);
  process.exit(1);
});
