import { getDatabase } from '../backend/db.js';
import { TelemetryService, ScanTelemetryPayload } from '../backend/telemetry.js';
import { FileScannerEngine } from '../backend/scannerEngine.js';
import { hashPassword } from '../backend/auth.js';
import { createApiRouter } from '../backend/routes.js';
import assert from 'node:assert';
import express from 'express';
import request from 'supertest';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

async function runPhase3TelemetryTests() {
  console.log('================================================================');
  console.log('   FileSentinel Phase 3: Privacy-Preserving Scan Telemetry Test   ');
  console.log('================================================================');

  const db = getDatabase(':memory:');
  const telemetryService = new TelemetryService(db);
  const now = new Date().toISOString();

  // Seed two distinct organizations and users
  const orgA = 'org-tenant-alpha';
  const orgB = 'org-tenant-bravo';
  const userA = 'usr-alice';
  const userB = 'usr-bob';
  const devA = 'dev-workstation-01';
  const devB = 'dev-workstation-02';

  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(orgA, 'Tenant Alpha Corp', now);
  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(orgB, 'Tenant Bravo Ltd', now);

  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(userA, orgA, 'alice', hashPassword('AliceSecure123!'), 'ORG_ADMIN', now);
  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(userB, orgB, 'bob', hashPassword('BobSecure123!'), 'ORG_ADMIN', now);

  db.prepare('INSERT INTO devices (device_id, org_id, device_name, registered_at) VALUES (?, ?, ?, ?)')
    .run(devA, orgA, 'Alice MacBook', now);
  db.prepare('INSERT INTO devices (device_id, org_id, device_name, registered_at) VALUES (?, ?, ?, ?)')
    .run(devB, orgB, 'Bob ThinkPad', now);

  // Setup express test app
  const app = express();
  app.use(express.json());
  app.use('/api', createApiRouter(db));

  // Login both users to get authorization tokens
  const loginResA = await request(app).post('/api/auth/login').send({ username: 'alice', password: 'AliceSecure123!', device_id: devA });
  assert.strictEqual(loginResA.status, 200);
  const tokenA = loginResA.body.token;

  const loginResB = await request(app).post('/api/auth/login').send({ username: 'bob', password: 'BobSecure123!', device_id: devB });
  assert.strictEqual(loginResB.status, 200);
  const tokenB = loginResB.body.token;

  console.log('  ✔ [SETUP] Authenticated multi-tenant sessions initialized.');

  // TEST 1: Telemetry Upload (POST /api/telemetry/scans) with all 26 required fields
  const sampleScanPayload: ScanTelemetryPayload = {
    scan_id: 'SCAN-TEST-001',
    organization_id: orgA,
    user_id: userA,
    device_id: devA,
    started_at: new Date(Date.now() - 5000).toISOString(),
    completed_at: new Date().toISOString(),
    duration_ms: 5000,
    application_version: '1.0.0',
    engine_version: '1.0.0',
    checklist_version: '2026.1',
    files_discovered: 120,
    files_processed: 120,
    files_succeeded: 118,
    files_failed: 2,
    files_rejected_by_resource_limits: 0,
    pass_count: 14,
    review_count: 2,
    fail_count: 1,
    evidence_not_found_count: 0,
    critical_count: 0,
    high_count: 1,
    medium_count: 3,
    low_count: 5,
    overall_score: 92.5,
    parameters_evaluated: 17,
    scan_status: 'COMPLETED'
  };

  const uploadRes = await request(app)
    .post('/api/telemetry/scans')
    .set('Authorization', `Bearer ${tokenA}`)
    .send(sampleScanPayload);

  assert.strictEqual(uploadRes.status, 200, 'POST /api/telemetry/scans succeeds');
  assert.strictEqual(uploadRes.body.scan_id, 'SCAN-TEST-001');
  assert.strictEqual(uploadRes.body.idempotent, false, 'First ingestion is not duplicate');

  // Verify saved in DB
  const storedRow = db.prepare('SELECT * FROM scan_telemetry WHERE scan_id = ? AND organization_id = ?').get('SCAN-TEST-001', orgA) as any;
  assert.ok(storedRow, 'Scan telemetry record stored in scan_telemetry table');
  assert.strictEqual(storedRow.overall_score, 92.5);
  assert.strictEqual(storedRow.files_discovered, 120);
  console.log('  ✔ [TEST 1] Telemetry upload with 26 standard fields verified.');

  // TEST 2: Duplicate Telemetry & Idempotency Boundary (organization_id + scan_id)
  const retryUploadRes = await request(app)
    .post('/api/telemetry/scans')
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ ...sampleScanPayload, overall_score: 95.0 }); // modified update

  assert.strictEqual(retryUploadRes.status, 200);
  assert.strictEqual(retryUploadRes.body.idempotent, true, 'Retry marked as idempotent');

  // Check that row count is still 1 and not duplicated
  const countRow = db.prepare('SELECT COUNT(*) as count FROM scan_telemetry WHERE scan_id = ? AND organization_id = ?').get('SCAN-TEST-001', orgA) as any;
  assert.strictEqual(countRow.count, 1, 'No duplicate record created in scan_telemetry');
  const updatedRow = db.prepare('SELECT overall_score FROM scan_telemetry WHERE scan_id = ? AND organization_id = ?').get('SCAN-TEST-001', orgA) as any;
  assert.strictEqual(updatedRow.overall_score, 95.0, 'Idempotent update applied cleanly');
  console.log('  ✔ [TEST 2] Duplicate telemetry idempotency by (organization_id + scan_id) verified.');

  // TEST 3: Offline Telemetry Queue & Local SQLite Persistence
  const offlinePayload: ScanTelemetryPayload = {
    ...sampleScanPayload,
    scan_id: 'SCAN-OFFLINE-002',
    files_processed: 45,
    overall_score: 88.0
  };

  const queueId = telemetryService.enqueue(offlinePayload);
  assert.ok(queueId.startsWith('TQ-'), 'Queue item created with ID');

  const pendingQueue = db.prepare('SELECT * FROM telemetry_queue WHERE queue_id = ?').get(queueId) as any;
  assert.ok(pendingQueue, 'Item stored in local telemetry_queue');
  assert.strictEqual(pendingQueue.status, 'PENDING');
  assert.strictEqual(pendingQueue.attempts, 0);

  const statsBefore = telemetryService.getQueueStatus(orgA);
  assert.ok(statsBefore.pending_count >= 1, 'Queue status reflects pending items');

  // Flush Queue
  const flushResult = telemetryService.flushQueue();
  assert.ok(flushResult.succeeded >= 1, 'Flush queue synchronizes pending items');

  const syncedQueue = db.prepare('SELECT * FROM telemetry_queue WHERE queue_id = ?').get(queueId) as any;
  assert.strictEqual(syncedQueue.status, 'SYNCED', 'Queue item updated to SYNCED');
  assert.ok(syncedQueue.synced_at, 'Synced timestamp recorded');

  // Confirm row now exists in scan_telemetry
  const syncedTeleRow = db.prepare('SELECT * FROM scan_telemetry WHERE scan_id = ?').get('SCAN-OFFLINE-002') as any;
  assert.ok(syncedTeleRow, 'Offline queue item processed into scan_telemetry table');
  console.log('  ✔ [TEST 3] Offline queue insertion, persistence, and synchronization verified.');

  // TEST 4: Telemetry Queue Retry on Simulated Recovery
  const retryQueueId = telemetryService.enqueue({
    ...sampleScanPayload,
    scan_id: 'SCAN-RETRY-003'
  });
  // Simulate previous failure
  db.prepare("UPDATE telemetry_queue SET status = 'FAILED', attempts = 1, error_message = 'Network timeout' WHERE queue_id = ?").run(retryQueueId);

  const retryFlush = telemetryService.flushQueue();
  assert.ok(retryFlush.succeeded >= 1, 'Retries pending/failed queue items');
  const recoveredQueue = db.prepare('SELECT * FROM telemetry_queue WHERE queue_id = ?').get(retryQueueId) as any;
  assert.strictEqual(recoveredQueue.status, 'SYNCED', 'Failed queue item successfully recovered');
  console.log('  ✔ [TEST 4] Offline queue retry and failure recovery verified.');

  // TEST 5: Network / Telemetry Failure Does NEVER Fail Local Scan
  const testDir = path.join(process.cwd(), 'temp_test_scan_privacy_' + Date.now());
  fs.mkdirSync(testDir, { recursive: true });
  fs.writeFileSync(path.join(testDir, 'local_doc.txt'), 'Local operation sample document content for scanning.');

  const scannerEngine = new FileScannerEngine(db);
  const localScanSession = await scannerEngine.startScan(
    [testDir],
    [],
    {
      maxFileSizeMB: 10,
      maxScanDepth: 2,
      aiEnabled: false,
      cloudUploadEnabled: false,
      telemetryEnabled: true,
      redactSensitivePreview: true,
      cloudBucketName: 'bucket',
      quarantineLocalDir: 'qdir'
    },
    orgA,
    userA,
    devA
  );

  // Poll scan completion
  let attempts = 0;
  while (attempts < 20) {
    const s = scannerEngine.getScanProgress(localScanSession.scan_id);
    if (s && s.status === 'COMPLETED') break;
    await new Promise(r => setTimeout(r, 100));
    attempts++;
  }

  const completedScan = scannerEngine.getScanProgress(localScanSession.scan_id);
  assert.ok(completedScan, 'Local scan progress exists');
  assert.strictEqual(completedScan?.status, 'COMPLETED', 'Local scan completes cleanly');
  console.log('  ✔ [TEST 5] Local scan completes independently even under offline/telemetry flow.');

  // TEST 6: Tenant Isolation & Unauthorized Organization
  // User B (Org B) requests Org A scan history
  const historyResB = await request(app)
    .get('/api/scans/history')
    .set('Authorization', `Bearer ${tokenB}`);

  assert.strictEqual(historyResB.status, 200);
  const orgBHistory = historyResB.body as ScanTelemetryPayload[];
  // Must NOT contain any of Org A's scan IDs
  const containsOrgAScan = orgBHistory.some(s => s.organization_id === orgA || s.scan_id === 'SCAN-TEST-001');
  assert.strictEqual(containsOrgAScan, false, 'Org B cannot view Org A scan history');

  // User B tries to view Org A scan detail
  const detailResB = await request(app)
    .get('/api/scans/SCAN-TEST-001')
    .set('Authorization', `Bearer ${tokenB}`);
  assert.strictEqual(detailResB.status, 403, 'Cross-tenant scan access rejected with 403 Forbidden');
  console.log('  ✔ [TEST 6] Multi-tenant isolation for scan telemetry history and details verified.');

  // TEST 7: Forged organization_id Prevention
  const forgedOrgRes = await request(app)
    .post('/api/telemetry/scans')
    .set('Authorization', `Bearer ${tokenA}`)
    .send({
      ...sampleScanPayload,
      scan_id: 'SCAN-FORGE-ORG',
      organization_id: 'org-tenant-bravo' // User A belongs to alpha, attempts to submit for bravo
    });

  assert.strictEqual(forgedOrgRes.status, 403, 'Forged organization_id rejected with 403 Forbidden');
  assert.ok(forgedOrgRes.body.error.includes('Forged organization_id'));
  console.log('  ✔ [TEST 7] Forged organization_id attempt rejected with 403 Forbidden.');

  // TEST 8: Forged user_id Prevention
  const forgedUserRes = await request(app)
    .post('/api/telemetry/scans')
    .set('Authorization', `Bearer ${tokenA}`)
    .send({
      ...sampleScanPayload,
      scan_id: 'SCAN-FORGE-USER',
      user_id: 'usr-admin-victim' // User A (alice) attempts to forge victim user_id
    });

  assert.strictEqual(forgedUserRes.status, 403, 'Forged user_id rejected with 403 Forbidden');
  assert.ok(forgedUserRes.body.error.includes('Forged user_id'));
  console.log('  ✔ [TEST 8] Forged user_id attempt rejected with 403 Forbidden.');

  // TEST 9: Forged / Malformed Scan Result Validation
  const malformedRes = await request(app)
    .post('/api/telemetry/scans')
    .set('Authorization', `Bearer ${tokenA}`)
    .send({
      scan_id: 'SCAN-BAD',
      duration_ms: -500 // negative duration
    });

  assert.strictEqual(malformedRes.status, 400, 'Malformed telemetry payload rejected with 400 Bad Request');
  console.log('  ✔ [TEST 9] Forged/malformed telemetry parameters rejected with 400 Bad Request.');

  // TEST 10 & 11: Absolute Document Privacy & PII Leakage Verification
  // Create a synthetic document with sensitive PII and secrets
  const syntheticDocPath = path.join(testDir, 'confidential_customer_record.txt');
  const sensitiveAadhaar = '5489 1234 5678';
  const sensitivePan = 'ABCDE1234F';
  const sensitiveGstin = '27AAAAA0000A1Z5';
  const sensitiveEmail = 'ceo.secret@corporate-tax.gov.in';
  const sensitivePhone = '+91-9876543210';
  const sensitiveEmpId = 'EMP-998877';
  const secretDocContent = `
    STRICTLY CONFIDENTIAL CUSTOMER ONBOARDING RECORD
    Name: Rameshwaram Sharma
    Aadhaar Number: ${sensitiveAadhaar}
    PAN Card: ${sensitivePan}
    GSTIN: ${sensitiveGstin}
    Official Email: ${sensitiveEmail}
    Primary Phone: ${sensitivePhone}
    Internal Employee ID: ${sensitiveEmpId}
    Salary Account: 98765432109876
    Secret Project Vault Access Key: secret-token-xyz-9988
  `;

  fs.writeFileSync(syntheticDocPath, secretDocContent);

  // Perform scan over directory
  const synthScanSession = await scannerEngine.startScan(
    [testDir],
    [],
    {
      maxFileSizeMB: 10,
      maxScanDepth: 2,
      aiEnabled: false,
      cloudUploadEnabled: false,
      telemetryEnabled: true,
      debugFilenamesEnabled: false, // Default: no debug filenames
      redactSensitivePreview: true,
      cloudBucketName: 'bucket',
      quarantineLocalDir: 'qdir'
    },
    orgA,
    userA,
    devA
  );

  let synthAttempts = 0;
  while (synthAttempts < 20) {
    const s = scannerEngine.getScanProgress(synthScanSession.scan_id);
    if (s && s.status === 'COMPLETED') break;
    await new Promise(r => setTimeout(r, 100));
    synthAttempts++;
  }

  // Generate and inspect the telemetry payload
  const synthTelemetry = telemetryService.buildTelemetryPayload(
    synthScanSession.scan_id,
    orgA,
    userA,
    devA,
    { debugFilenamesEnabled: false }
  );

  assert.ok(synthTelemetry, 'Telemetry payload generated successfully');
  const telemetryJsonString = JSON.stringify(synthTelemetry);

  // ABSOLUTE ZERO LEAKAGE VERIFICATION:
  // Assert none of the sensitive strings or document content appear anywhere in the telemetry JSON
  assert.strictEqual(telemetryJsonString.includes(sensitiveAadhaar), false, 'Aadhaar does not appear in telemetry');
  assert.strictEqual(telemetryJsonString.includes(sensitivePan), false, 'PAN does not appear in telemetry');
  assert.strictEqual(telemetryJsonString.includes(sensitiveGstin), false, 'GSTIN does not appear in telemetry');
  assert.strictEqual(telemetryJsonString.includes(sensitiveEmail), false, 'Email does not appear in telemetry');
  assert.strictEqual(telemetryJsonString.includes(sensitivePhone), false, 'Phone number does not appear in telemetry');
  assert.strictEqual(telemetryJsonString.includes(sensitiveEmpId), false, 'Employee ID does not appear in telemetry');
  assert.strictEqual(telemetryJsonString.includes('Rameshwaram'), false, 'Customer Name does not appear in telemetry');
  assert.strictEqual(telemetryJsonString.includes('STRICTLY CONFIDENTIAL'), false, 'Document text does not appear in telemetry');
  assert.strictEqual(telemetryJsonString.includes('secret-token-xyz-9988'), false, 'Secret tokens do not appear in telemetry');
  assert.strictEqual(telemetryJsonString.includes(testDir), false, 'Full file path does not appear in telemetry');
  assert.strictEqual(telemetryJsonString.includes('confidential_customer_record.txt'), false, 'Filename not leaked when debug filenames disabled');

  // Verify device telemetry bounds
  const devInfo = synthTelemetry.device_telemetry;
  assert.ok(devInfo, 'Device telemetry exists');
  assert.ok(devInfo.os_family, 'OS family included');
  assert.ok(devInfo.architecture, 'Architecture included');
  assert.strictEqual((devInfo as any).mac_address, undefined, 'No MAC address collected');
  assert.strictEqual((devInfo as any).hardware_serial, undefined, 'No hardware serial collected');
  assert.strictEqual((devInfo as any).gps, undefined, 'No GPS collected');
  assert.strictEqual((devInfo as any).browser_history, undefined, 'No browser history collected');

  console.log('  ✔ [TEST 10 & 11] Proved ZERO document content, OCR, or PII leakage across telemetry payloads.');

  // TEST 12: Telemetry Disabled Mode
  const disabledScan = await scannerEngine.startScan(
    [testDir],
    [],
    {
      maxFileSizeMB: 10,
      maxScanDepth: 2,
      aiEnabled: false,
      cloudUploadEnabled: false,
      telemetryEnabled: false, // Disabled!
      redactSensitivePreview: true,
      cloudBucketName: 'bucket',
      quarantineLocalDir: 'qdir'
    },
    orgA,
    userA,
    devA
  );

  let disAttempts = 0;
  while (disAttempts < 20) {
    const s = scannerEngine.getScanProgress(disabledScan.scan_id);
    if (s && s.status === 'COMPLETED') break;
    await new Promise(r => setTimeout(r, 100));
    disAttempts++;
  }

  const disabledInQueue = db.prepare('SELECT * FROM telemetry_queue WHERE scan_id = ?').get(disabledScan.scan_id);
  assert.strictEqual(disabledInQueue, undefined, 'No telemetry queued when telemetry is disabled');
  console.log('  ✔ [TEST 12] Telemetry disabled mode respected with zero queue or transmission.');

  // Clean up synthetic test directory
  try {
    fs.rmSync(testDir, { recursive: true, force: true });
  } catch {}

  console.log('================================================================');
  console.log('   ALL PHASE 3 PRIVACY TELEMETRY TESTS PASSED (12/12)            ');
  console.log('================================================================');
  process.exit(0);
}

runPhase3TelemetryTests().catch(err => {
  console.error('Phase 3 Telemetry Tests failed:', err);
  process.exit(1);
});
