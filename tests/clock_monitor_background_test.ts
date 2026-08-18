import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { getDatabase } from '../backend/db.js';
import { ClockMonitorService } from '../backend/licensing/clockMonitor.js';
import { OfflineLicenseEngine, getOrCreateDevKeyPair } from '../backend/licensing/offlineLicense.js';
import { ProtectedLicenseStore } from '../backend/licensing/protectedLicenseStore.js';

async function runTest() {
  console.log('================================================================');
  console.log('          FILE-SENTINEL: Clock Monitor Background Service Test ');
  console.log('================================================================');

  const db = getDatabase(':memory:');
  const tempStorePath = path.join(process.cwd(), `test_store_clock_monitor_${Math.floor(Math.random() * 100000)}.dat`);

  try {
    // 1. Initialize Tables & Dummy Lease
    const licEngine = new OfflineLicenseEngine(db);
    const orgId = 'test-org-clock-monitor';
    const leasePayload = {
      licenseId: 'LIC-TEST-002',
      organizationId: orgId,
      deviceLimit: 50,
      modules: ['SCAN', 'AUDIT'],
      issuedAt: new Date().toISOString(),
      notBefore: new Date(Date.now() - 3600000).toISOString(),
      expiresAt: new Date(Date.now() + 10 * 86400000).toISOString(),
      licenseVersion: '1.0.0'
    };

    const devKeyPair = getOrCreateDevKeyPair();

    const signedLease = OfflineLicenseEngine.signLease(leasePayload, devKeyPair.privateKey, 'fs-dev-key');

    // Store in OS-Protected Store
    const store = new ProtectedLicenseStore(tempStorePath);
    const initialFp = ProtectedLicenseStore.getMachineFingerprint();
    store.saveState({
      organizationId: orgId,
      licenseId: 'LIC-TEST-002',
      signedLeaseJson: JSON.stringify(signedLease),
      machineFingerprint: initialFp,
      maxSeenTimestampIso: new Date().toISOString(),
      lastTrustedTimestampIso: new Date().toISOString(),
      status: 'ACTIVE',
      graceUntilIso: new Date(Date.now() + 13 * 86400000).toISOString(),
      expiresAtIso: new Date(Date.now() + 10 * 86400000).toISOString(),
      clockRollbackDetected: false,
      updatedAtIso: new Date().toISOString(),
      maxSeenVersion: '1.0.0',
      maxSeenIssuedAtIso: leasePayload.issuedAt
    });

    // Populate SQLite organization and license_state
    try {
      db.prepare(`
        INSERT INTO organizations (org_id, name, created_at)
        VALUES (?, ?, ?)
      `).run(orgId, 'Test Organization', new Date().toISOString());
    } catch {}

    db.prepare(`
      INSERT INTO license_state (
        id, org_id, license_id, lease_jwt, license_version, device_limit,
        modules_json, issued_at, not_before, expires_at, grace_until,
        last_trusted_timestamp, clock_rollback_detected, status, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'ACTIVE', ?)
    `).run(
      'state-002', orgId, 'LIC-TEST-002', JSON.stringify(signedLease), '1.0.0', 50,
      JSON.stringify(['SCAN']), leasePayload.issuedAt, leasePayload.notBefore,
      leasePayload.expiresAt, leasePayload.expiresAt, new Date().toISOString(),
      new Date().toISOString()
    );

    // 2. Validate standard state before rollback detection
    console.log('  ✔ [SETUP] Database and OS-protected license stores initialized.');
    let validation = licEngine.validateCurrentLicense({ orgId, protectedStorePath: tempStorePath });
    assert.strictEqual(validation.valid, true, 'License should initially be valid.');
    assert.strictEqual(validation.status, 'ACTIVE', 'License status should initially be ACTIVE.');

    // 3. Initialize ClockMonitorService
    const monitor = new ClockMonitorService(db, {
      driftThresholdMs: 2000,
      checkIntervalMs: 500,
      protectedStorePath: tempStorePath
    });

    let callbackTriggered = false;
    let callbackReason = '';
    monitor.start((reason) => {
      callbackTriggered = true;
      callbackReason = reason;
    });

    // 4. Test Case 1: Manual Trigger Simulation of Rollback
    console.log('  ✔ [TEST 1] Manual rollback trigger simulation execution...');
    monitor.triggerClockRollback('Forced simulation', (reason) => {
      assert.strictEqual(reason, 'Forced simulation');
    });

    // Verify blocking status in DB
    const dbRow = db.prepare('SELECT status, clock_rollback_detected FROM license_state WHERE org_id = ?').get(orgId) as any;
    assert.strictEqual(dbRow.status, 'CLOCK_ROLLBACK_DETECTED');
    assert.strictEqual(dbRow.clock_rollback_detected, 1);

    // Verify blocking status on disk
    const diskState = store.loadState();
    assert.strictEqual(diskState?.status, 'CLOCK_ROLLBACK_DETECTED');
    assert.strictEqual(diskState?.clockRollbackDetected, true);

    // Validate that license engine now blocks scan
    validation = licEngine.validateCurrentLicense({ orgId, protectedStorePath: tempStorePath });
    assert.strictEqual(validation.valid, false);
    assert.strictEqual(validation.status, 'CLOCK_ROLLBACK_DETECTED');
    assert.strictEqual(validation.canScan, false, 'Scanning MUST be blocked.');
    console.log('  ✔ [TEST 1] Scan blocking under CLOCK_ROLLBACK_DETECTED verified successfully.');

    // Reset rollback block for clock check verification
    db.prepare("UPDATE license_state SET clock_rollback_detected = 0, status = 'ACTIVE' WHERE org_id = ?").run(orgId);
    store.saveState({
      ...diskState!,
      clockRollbackDetected: false,
      status: 'ACTIVE'
    });

    // 5. Test Case 2: Monotonic progression mismatch against stored timestamps
    console.log('  ✔ [TEST 2] Verifying clock rollback via ahead max-seen store timestamp...');
    // Artificially write a future max seen timestamp in the protected store (e.g., 1 day in future)
    const futureIso = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    store.saveState({
      ...store.loadState()!,
      maxSeenTimestampIso: futureIso
    });

    let detected = false;
    monitor.checkClock((reason) => {
      detected = true;
      assert.ok(reason.includes('significantly behind last max seen trusted time'));
    });

    assert.strictEqual(detected, true, 'Backward time jump against max seen should be detected.');
    console.log('  ✔ [TEST 2] Future-dated max-seen protection verified successfully.');

  } finally {
    // Cleanup temporary protected store
    if (fs.existsSync(tempStorePath)) {
      fs.unlinkSync(tempStorePath);
    }
  }

  console.log('================================================================');
  console.log('          ALL CLOCK MONITOR SECURITY TESTS PASSED!');
  console.log('================================================================');
}

runTest().catch(err => {
  console.error('Test execution failed with error:', err);
  process.exit(1);
});
