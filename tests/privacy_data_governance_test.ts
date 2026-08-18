import { getDatabase } from '../backend/db.js';
import { TelemetryService } from '../backend/telemetry.js';
import { PrivacyGovernanceService, DataClassificationCategory, SENSITIVE_PATTERNS } from '../backend/privacyGovernance.js';
import { FileScannerEngine } from '../backend/scannerEngine.js';
import { hashPassword } from '../backend/auth.js';
import { createApiRouter } from '../backend/routes.js';
import assert from 'node:assert';
import express from 'express';
import request from 'supertest';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

async function runPrivacyGovernanceTestSuite() {
  console.log('========================================================================');
  console.log('  COMMERCIALIZATION PHASE 8: Privacy-First Data Governance Test Suite  ');
  console.log('========================================================================');

  const db = getDatabase(':memory:');
  const telemetryService = new TelemetryService(db);
  const privacyService = new PrivacyGovernanceService(db);
  const scannerEngine = new FileScannerEngine(db);
  const now = new Date().toISOString();

  // 1. Setup multi-tenant organizations
  const orgA = 'org-privacy-alpha';
  const orgB = 'org-privacy-bravo';
  const userA = 'usr-admin-alpha';
  const userB = 'usr-admin-bravo';
  const devA = 'dev-local-station-01';
  const devB = 'dev-local-station-02';

  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(orgA, 'Alpha Healthcare & Finance', now);
  db.prepare('INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run(orgB, 'Bravo Telecalling Agency', now);

  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(userA, orgA, 'alpha_admin', hashPassword('AlphaPass123!'), 'ORG_ADMIN', now);
  db.prepare('INSERT INTO users (user_id, org_id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(userB, orgB, 'bravo_admin', hashPassword('BravoPass123!'), 'ORG_ADMIN', now);

  db.prepare('INSERT INTO devices (device_id, org_id, device_name, registered_at) VALUES (?, ?, ?, ?)')
    .run(devA, orgA, 'Alpha MacBook Pro', now);
  db.prepare('INSERT INTO devices (device_id, org_id, device_name, registered_at) VALUES (?, ?, ?, ?)')
    .run(devB, orgB, 'Bravo Workstation', now);

  const app = express();
  app.use(express.json());
  app.use('/api', createApiRouter(db));

  const loginResA = await request(app).post('/api/auth/login').send({ username: 'alpha_admin', password: 'AlphaPass123!', device_id: devA });
  assert.strictEqual(loginResA.status, 200);
  const tokenA = loginResA.body.token;

  const loginResB = await request(app).post('/api/auth/login').send({ username: 'bravo_admin', password: 'BravoPass123!', device_id: devB });
  assert.strictEqual(loginResB.status, 200);
  const tokenB = loginResB.body.token;

  console.log('  ✔ [SETUP] Authenticated multi-tenant sessions established.');

  // =========================================================================
  // TEST 1: Formal Data Classification Model Verification
  // =========================================================================
  console.log('\n--- TEST 1: Formal Data Classification Model ---');
  const manifest = privacyService.getGovernanceManifest();
  assert.strictEqual(manifest.core_principle, 'SCAN LOCAL. STORE DOCUMENTS LOCAL. TRANSMIT MINIMUM METADATA.');
  assert(Array.isArray(manifest.classification_registry), 'Classification registry must be an array');
  assert(manifest.classification_registry.length >= 15, 'Must contain comprehensive classified fields');

  const catAFields = manifest.classification_registry.filter(f => f.category === DataClassificationCategory.LOCAL_ONLY_SENSITIVE);
  const catBFields = manifest.classification_registry.filter(f => f.category === DataClassificationCategory.TELEMETRY_SAFE_METADATA);
  const catCFields = manifest.classification_registry.filter(f => f.category === DataClassificationCategory.OPTIONAL_CLOUD_EVIDENCE);

  assert(catAFields.length >= 10, 'Category A (Local-Only Sensitive) must classify documents, text, OCR, PII, PAN, Aadhaar, GSTIN, Employee IDs, Phone, Email, Certificate numbers');
  assert(catBFields.length >= 8, 'Category B (Telemetry-Safe) must classify scan ID, org ID, user ID, device ID, timestamps, duration, counts, stats, versions');
  assert(catCFields.length >= 1, 'Category C (Optional Cloud Evidence) must classify explicit manual upload artifacts');

  // Verify all Category A fields have transmission_policy === 'NEVER_TRANSMIT'
  for (const field of catAFields) {
    assert.strictEqual(field.transmission_policy, 'NEVER_TRANSMIT', `Field ${field.field_name} must NEVER be transmitted`);
    assert.strictEqual(field.storage_location, 'LOCAL_SQLITE_ONLY', `Field ${field.field_name} must stay in LOCAL_SQLITE_ONLY`);
  }

  console.log(`  ✔ Category A Local-Only Fields verified: ${catAFields.map(f => f.field_name).join(', ')}`);
  console.log(`  ✔ Category B Telemetry-Safe Fields verified: ${catBFields.map(f => f.field_name).join(', ')}`);
  console.log(`  ✔ Category C Optional Cloud Evidence verified: ${catCFields.map(f => f.field_name).join(', ')}`);

  // =========================================================================
  // TEST 2: Zero-Leakage Prevention Test with Synthetic Sensitive Documents
  // =========================================================================
  console.log('\n--- TEST 2: Zero-Leakage Prevention with Highly Sensitive Data ---');
  const tempTestDir = path.join(process.cwd(), 'test_privacy_sandbox_' + crypto.randomBytes(4).toString('hex'));
  fs.mkdirSync(tempTestDir, { recursive: true });

  const sensitiveSampleText = `
    CONFIDENTIAL TELECALLING AGENT ROSTER & COMPLIANCE FILE
    ---------------------------------------------------------
    Agent Name: Rajesh Ramesh Sharma
    PAN Identifier: BKXPG9988K
    Aadhaar Number: 4321 8765 9012
    GSTIN Statutory: 27AAAAA0000A1Z5
    Employee ID: EMP-99014
    Official Email: compliance.officer@confidential-recovery.co.in
    Contact Mobile: +91 98765 43210
    Bank Account Number: 9182736450192837
    IFSC Code: HDFC0000123
    DRA Certificate Number: DRA-2024-99812
    Police Verification Ref: PV-ACK-88301
    
    Context Evidence: Agent completed 100-hour mandatory telecalling DRA compliance training on 15-Jan-2024.
    Police verification verified clear of criminal background on 20-Jan-2024.
  `;

  const sensitiveFilePath = path.join(tempTestDir, 'agent_compliance_dossier.txt');
  fs.writeFileSync(sensitiveFilePath, sensitiveSampleText, 'utf-8');

  // Perform a scan on this sensitive folder
  const scanSession = await scannerEngine.startScan([tempTestDir], [], undefined, orgA, userA, devA);
  while (true) {
    const p = scannerEngine.getScanProgress(scanSession.scan_id);
    if (p && p.status === 'COMPLETED') break;
    await new Promise(r => setTimeout(r, 50));
  }

  console.log(`  ✔ Local scan completed for scan ID: ${scanSession.scan_id}`);

  // Fetch the inspection report for this scan
  const inspection = privacyService.inspectScanTelemetryPayload(
    scanSession.scan_id,
    orgA,
    userA,
    devA,
    { telemetryEnabled: true, debugFilenamesEnabled: false }
  );

  assert.strictEqual(inspection.verdict, 'APPROVED_FOR_TRANSMISSION');
  assert.strictEqual(inspection.category_a_violations_detected, 0, 'Zero Category A sensitive violations allowed in telemetry payload');

  const rawJsonString = JSON.stringify(inspection.raw_payload_preview);

  // Assert absolutely NONE of the sensitive identifiers or document texts appear in the payload string
  assert(!rawJsonString.includes('BKXPG9988K'), 'LEAK: PAN BKXPG9988K found in telemetry payload!');
  assert(!rawJsonString.includes('4321 8765 9012'), 'LEAK: Aadhaar 4321 8765 9012 found in telemetry payload!');
  assert(!rawJsonString.includes('27AAAAA0000A1Z5'), 'LEAK: GSTIN 27AAAAA0000A1Z5 found in telemetry payload!');
  assert(!rawJsonString.includes('compliance.officer@confidential-recovery.co.in'), 'LEAK: Email found in telemetry payload!');
  assert(!rawJsonString.includes('98765 43210'), 'LEAK: Phone number found in telemetry payload!');
  assert(!rawJsonString.includes('EMP-99014'), 'LEAK: Employee ID found in telemetry payload!');
  assert(!rawJsonString.includes('9182736450192837'), 'LEAK: Bank account found in telemetry payload!');
  assert(!rawJsonString.includes('Rajesh Ramesh Sharma'), 'LEAK: PII Person name found in telemetry payload!');
  assert(!rawJsonString.includes('DRA-2024-99812'), 'LEAK: Certificate number found in telemetry payload!');
  assert(!rawJsonString.includes('DRA compliance training'), 'LEAK: Evidence snippet context found in telemetry payload!');

  console.log('  ✔ Verified ZERO leaks across PAN, Aadhaar, GSTIN, Email, Phone, Employee ID, Bank Account, PII Names, and Evidence Snippets.');

  // Clean up synthetic test folder
  try {
    fs.rmSync(tempTestDir, { recursive: true, force: true });
  } catch (e) {}

  // =========================================================================
  // TEST 3: Telemetry Debugger Endpoint & Multi-Tenant Isolation
  // =========================================================================
  console.log('\n--- TEST 3: Telemetry Debugger Endpoint & Multi-Tenant Isolation ---');
  const debugResA = await request(app)
    .get(`/api/privacy/telemetry-preview/${scanSession.scan_id}`)
    .set('Authorization', `Bearer ${tokenA}`);

  assert.strictEqual(debugResA.status, 200);
  assert.strictEqual(debugResA.body.verdict, 'APPROVED_FOR_TRANSMISSION');
  assert.strictEqual(debugResA.body.category_a_violations_detected, 0);
  assert(debugResA.body.field_audits.length > 0);

  // Tenant B attempts to inspect Tenant A's scan telemetry payload -> Must be 403 Forbidden
  const debugResB = await request(app)
    .get(`/api/privacy/telemetry-preview/${scanSession.scan_id}`)
    .set('Authorization', `Bearer ${tokenB}`);

  assert.strictEqual(debugResB.status, 403, 'Cross-tenant telemetry inspection must return 403 Forbidden');
  console.log('  ✔ Telemetry inspection endpoint verified with robust multi-tenant authorization enforcement.');

  // =========================================================================
  // TEST 4: Configurable Data Retention & Local Durability Guarantee
  // =========================================================================
  console.log('\n--- TEST 4: Configurable Cloud Retention & Local Customer Data Durability ---');
  // 1. Get default retention policy
  const getPolicyRes = await request(app)
    .get('/api/privacy/retention-policy')
    .set('Authorization', `Bearer ${tokenA}`);
  assert.strictEqual(getPolicyRes.status, 200);
  assert.strictEqual(getPolicyRes.body.cloud_metadata_retention_days, 90);

  // 2. Update retention policy to 30 days
  const updatePolicyRes = await request(app)
    .post('/api/privacy/retention-policy')
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ cloud_metadata_retention_days: 30, auto_purge_enabled: true });
  assert.strictEqual(updatePolicyRes.status, 200);
  assert.strictEqual(updatePolicyRes.body.policy.cloud_metadata_retention_days, 30);

  // 3. Seed an old telemetry record (45 days old) and a recent telemetry record (5 days old)
  const oldDate = new Date(Date.now() - 45 * 24 * 3600 * 1000).toISOString();
  const recentDate = new Date(Date.now() - 5 * 24 * 3600 * 1000).toISOString();

  db.prepare(`
    INSERT INTO scan_telemetry (
      scan_id, organization_id, user_id, device_id, started_at, completed_at, duration_ms,
      application_version, engine_version, checklist_version, files_discovered, files_processed,
      files_succeeded, files_failed, files_rejected_by_resource_limits, pass_count, review_count,
      fail_count, evidence_not_found_count, critical_count, high_count, medium_count, low_count,
      overall_score, parameters_evaluated, scan_status, created_at
    ) VALUES (
      'old-scan-telemetry-01', ?, 'usr-admin-alpha', 'dev-01', ?, ?, 1000,
      '1.0.0', '1.0.0', '2026.1', 10, 10, 10, 0, 0, 8, 2, 0, 0, 0, 0, 1, 1, 90, 24, 'COMPLETED', ?
    )
  `).run(orgA, oldDate, oldDate, oldDate);

  db.prepare(`
    INSERT INTO scan_telemetry (
      scan_id, organization_id, user_id, device_id, started_at, completed_at, duration_ms,
      application_version, engine_version, checklist_version, files_discovered, files_processed,
      files_succeeded, files_failed, files_rejected_by_resource_limits, pass_count, review_count,
      fail_count, evidence_not_found_count, critical_count, high_count, medium_count, low_count,
      overall_score, parameters_evaluated, scan_status, created_at
    ) VALUES (
      'recent-scan-telemetry-02', ?, 'usr-admin-alpha', 'dev-01', ?, ?, 1000,
      '1.0.0', '1.0.0', '2026.1', 10, 10, 10, 0, 0, 8, 2, 0, 0, 0, 0, 1, 1, 90, 24, 'COMPLETED', ?
    )
  `).run(orgA, recentDate, recentDate, recentDate);

  // Count local customer records before purge
  const localScansBefore = (db.prepare('SELECT COUNT(*) as count FROM scans').get() as any).count;
  const localFilesBefore = (db.prepare('SELECT COUNT(*) as count FROM files').get() as any).count;

  // 4. Execute Purge
  const purgeRes = await request(app)
    .post('/api/privacy/purge-cloud-telemetry')
    .set('Authorization', `Bearer ${tokenA}`);

  assert.strictEqual(purgeRes.status, 200);
  assert.strictEqual(purgeRes.body.purged_telemetry_records, 1, 'Exactly 1 old telemetry record (>30 days) must be purged');

  // Verify recent telemetry record is still present
  const recentRecord = db.prepare("SELECT * FROM scan_telemetry WHERE scan_id = 'recent-scan-telemetry-02'").get();
  assert(recentRecord, 'Recent telemetry record must NOT be purged');

  const oldRecord = db.prepare("SELECT * FROM scan_telemetry WHERE scan_id = 'old-scan-telemetry-01'").get();
  assert(!oldRecord, 'Old telemetry record must be purged');

  // 5. CRITICAL DURABILITY CHECK: Local customer records must be 100% intact
  const localScansAfter = (db.prepare('SELECT COUNT(*) as count FROM scans').get() as any).count;
  const localFilesAfter = (db.prepare('SELECT COUNT(*) as count FROM files').get() as any).count;

  assert.strictEqual(localScansAfter, localScansBefore, 'Local customer scans table was modified during cloud purge! Violates local durability guarantee!');
  assert.strictEqual(localFilesAfter, localFilesBefore, 'Local customer files table was modified during cloud purge! Violates local durability guarantee!');

  console.log(`  ✔ Cloud purge purged expired records while preserving ${localScansAfter} local scans and ${localFilesAfter} local file records.`);

  // =========================================================================
  // TEST 5: Regulatory Compliance Support Statement
  // =========================================================================
  console.log('\n--- TEST 5: Regulatory & Legal Compliance Support Statement ---');
  const govRes = await request(app).get('/api/privacy/governance');
  assert.strictEqual(govRes.status, 200);
  assert(govRes.body.regulatory_readiness.disclaimer.includes('support organizational compliance'));
  assert(govRes.body.regulatory_readiness.disclaimer.includes('does not constitute automatic or official certification'));
  console.log('  ✔ Regulatory support statement correctly positions FileSentinel as a compliance support tool without unsupported claims.');

  console.log('\n========================================================================');
  console.log('  ✔ ALL COMMERCIAL PHASE 8 PRIVACY-FIRST DATA GOVERNANCE TESTS PASSED   ');
  console.log('========================================================================\n');
}

runPrivacyGovernanceTestSuite().then(() => {
  process.exit(0);
}).catch(err => {
  console.error('Phase 8 Test Suite Failed:', err);
  process.exit(1);
});
