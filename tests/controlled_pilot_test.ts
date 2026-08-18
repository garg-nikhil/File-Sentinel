import { getDatabase } from '../backend/db.js';
import { PilotService } from '../backend/pilotService.js';
import { LicensingEngine } from '../backend/licensing.js';
import assert from 'node:assert';

export function runControlledPilotTests() {
  console.log('[Test] Running Controlled Pilot Mode Test Suite (Phase 11)...');
  const db = getDatabase();
  const pilotService = new PilotService(db);
  const licensingEngine = new LicensingEngine(db);

  // 1. Test Pilot Organization Creation & Trial License
  const pilotResult = pilotService.createPilotOrganization({
    org_name: 'Test Pilot Corp',
    admin_username: 'pilotadmin_' + Date.now(),
    admin_password: 'TestPassword123!',
    duration_days: 14,
    admin_user_id: 'sys-admin-1'
  });

  assert.strictEqual(pilotResult.success, true, 'Pilot organization should be created successfully');
  assert.ok(pilotResult.org_id, 'Pilot org_id should be returned');
  assert.strictEqual(pilotResult.trial_status, 'ACTIVE', 'Trial status should be ACTIVE');

  // 2. Test License Validation & Days Remaining
  const validation = licensingEngine.validateLicense(pilotResult.org_id, {
    deviceId: pilotResult.device_id,
    requiredFeature: 'LOCAL_SCANNING',
    isStartingScan: true
  });

  assert.strictEqual(validation.valid, true, 'Pilot trial license should be valid for scanning');
  assert.strictEqual(validation.status, 'TRIAL', 'License status should be TRIAL');
  assert.ok(validation.days_remaining !== undefined && validation.days_remaining > 0, 'Days remaining should be greater than 0');

  // 3. Test Pilot Telemetry Events Recording
  pilotService.recordTelemetry('first_scan', pilotResult.org_id, pilotResult.user_id, pilotResult.device_id, { test: true });
  pilotService.recordTelemetry('report_export', pilotResult.org_id, pilotResult.user_id, pilotResult.device_id, { report_id: 'rep-1' });

  const events = db.prepare('SELECT * FROM pilot_telemetry_events WHERE org_id = ?').all(pilotResult.org_id) as any[];
  assert.ok(events.length >= 3, 'Should have recorded activation, first_scan, and report_export telemetry events');
  assert.ok(events.some(e => e.event_type === 'activation'), 'Should record activation event');
  assert.ok(events.some(e => e.event_type === 'first_scan'), 'Should record first_scan event');
  assert.ok(events.some(e => e.event_type === 'report_export'), 'Should record report_export event');

  // 4. Test Pilot List & Management
  const pilots = pilotService.listPilots();
  const pilotRecord = pilots.find(p => p.org_id === pilotResult.org_id);
  assert.ok(pilotRecord, 'Pilot organization should appear in pilot list');
  assert.strictEqual(pilotRecord.current_devices, 1, 'Current active devices count should be 1');

  // 5. Test Pilot Extension
  const extendRes = pilotService.extendPilotTrial(pilotResult.org_id, 7, 'sys-admin-1');
  assert.strictEqual(extendRes.success, true, 'Trial extension should succeed');

  // 6. Test Pilot Conversion to Paid
  const convertRes = pilotService.convertPilotToPaid(pilotResult.org_id, 'plan-professional', 'sys-admin-1');
  assert.strictEqual(convertRes.success, true, 'Pilot conversion to paid should succeed');

  const updatedLic = licensingEngine.getLicenseForOrg(pilotResult.org_id);
  assert.strictEqual(updatedLic?.trial_status, 'CONVERTED', 'Trial status should be CONVERTED');
  assert.strictEqual(updatedLic?.status, 'ACTIVE', 'License status should become ACTIVE');

  console.log('[Test] Controlled Pilot Mode Test Suite PASSED successfully.');
}

if (process.argv[1] && process.argv[1].endsWith('controlled_pilot_test.ts')) {
  try {
    runControlledPilotTests();
    process.exit(0);
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}
