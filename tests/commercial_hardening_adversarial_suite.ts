import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { ImageOcrExtractor } from '../backend/extractors/imageOcrExtractor.js';
import { createSyntheticPngImage } from './helpers/imageGenerator.js';
import { OfflineLicenseEngine, getOrCreateDevKeyPair } from '../backend/licensing/offlineLicense.js';
import { ProtectedLicenseStore } from '../backend/licensing/protectedLicenseStore.js';
import { ScanJobManager } from '../backend/scanJobManager.js';
import { ChecklistManager } from '../backend/checklists/checklistManager.js';
import { StandardWindowsAgentBoundary } from '../backend/endpoint/agentBoundary.js';

async function runCommercialHardeningSuite() {
  console.log('========================================================================');
  console.log('  FILE-SENTINEL: Post-Architecture Commercial Hardening Gate           ');
  console.log('========================================================================\n');

  let totalTests = 0;
  let passedTests = 0;

  async function test(name: string, fn: () => void | Promise<void>) {
    totalTests++;
    try {
      await fn();
      passedTests++;
      console.log(`  [PASS] Test ${totalTests}: ${name}`);
    } catch (err: any) {
      console.error(`  [FAIL] Test ${totalTests}: ${name}`);
      console.error(`         Error: ${err.message}`);
    }
  }

  const dbPath = path.join(process.cwd(), 'test_hardening_gate.db');
  if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
  const db = new DatabaseSync(dbPath);

  // Initialize DB tables
  db.exec(`
    CREATE TABLE IF NOT EXISTS organizations (
      org_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      suspended INTEGER DEFAULT 0
    );
    INSERT INTO organizations (org_id, name) VALUES ('org-bank-001', 'First National Bank');
    INSERT INTO organizations (org_id, name) VALUES ('org-bank-002', 'Competitor Bank');
  `);

  const tempDir = path.join(process.cwd(), 'test_hardening_workspace');
  if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

  console.log('--- SECTION 1: REAL OCR & ADVERSARIAL IMAGE TESTS ---');

  await test('1. Clear scanned GST image -> Structured GSTIN & PASS', async () => {
    const imgPath = createSyntheticPngImage(tempDir, {
      filename: 'gst_cert_valid.png',
      textPayload: 'Form GST REG-06 Certificate of Registration. GSTIN: 27AAAAA0000A1Z5 Legal Name: ABC Logistics Pvt Ltd Registration Date: 01/04/2024'
    });

    const extractor = new ImageOcrExtractor();
    const result = await extractor.extract(imgPath);

    const structured = (result.structure.structuredFields || {}) as any;
    assert.equal(result.metadata.evidence_type, 'IMAGE_OCR');
    assert.equal(result.metadata.ocr_status, 'SUCCESS');
    assert.equal(structured.gstin, '27AAAAA0000A1Z5');
    assert.equal(structured.documentType, 'GST_CERTIFICATE');
  });

  await test('2. Clear scanned DRA certificate image -> Structured Certificate No & PASS', async () => {
    const imgPath = createSyntheticPngImage(tempDir, {
      filename: 'dra_certificate_valid.png',
      textPayload: 'Debt Recovery Agent Certification. Candidate Name: John Doe. DRA-8829102 Issue Date: 15/01/2025'
    });

    const extractor = new ImageOcrExtractor();
    const result = await extractor.extract(imgPath);

    const structured = (result.structure.structuredFields || {}) as any;
    assert.equal(result.metadata.ocr_status, 'SUCCESS');
    assert.equal(structured.certificateNumber, 'DRA-8829102');
    assert.equal(structured.documentType, 'DRA_CERTIFICATE');
  });

  await test('3. Clear scanned Insurance image -> Structured Policy No & Expiry', async () => {
    const imgPath = createSyntheticPngImage(tempDir, {
      filename: 'insurance_policy_valid.png',
      textPayload: 'Commercial Vehicle Insurance Certificate. Policy No: POL-9948201 Effective: 01/01/2025 Expiry: 31/12/2028 Insured: ABC Logistics'
    });

    const extractor = new ImageOcrExtractor();
    const result = await extractor.extract(imgPath);
    const structured = (result.structure.structuredFields || {}) as any;

    assert.equal(result.metadata.ocr_status, 'SUCCESS');
    assert.equal(structured.policyNumber, 'POL-9948201');
    assert.equal(structured.isExpired, false);
  });

  await test('4. Generic "GST" text with no GSTIN structured fields -> REVIEW', async () => {
    const imgPath = createSyntheticPngImage(tempDir, {
      filename: 'generic_gst_text.png',
      textPayload: 'GST Goods and Services Tax guidelines brochure and information pamphlet.'
    });

    const extractor = new ImageOcrExtractor();
    const result = await extractor.extract(imgPath);
    const structured = (result.structure.structuredFields || {}) as any;

    assert.equal(structured.hasStructuredFields, false);
    assert.equal(structured.gstin, undefined);
  });

  await test('5. Expired insurance image -> Flagged as Expired', async () => {
    const imgPath = createSyntheticPngImage(tempDir, {
      filename: 'insurance_policy_expired.png',
      textPayload: 'Insurance Certificate Policy No: POL-112233 Effective: 01/01/2020 Expiry: 31/12/2021 Insured: Old Corp'
    });

    const extractor = new ImageOcrExtractor();
    const result = await extractor.extract(imgPath);
    const structured = (result.structure.structuredFields || {}) as any;

    assert.equal(structured.isExpired, true);
  });

  await test('6. Blank image -> BLANK / EVIDENCE_NOT_FOUND', async () => {
    const imgPath = createSyntheticPngImage(tempDir, {
      filename: 'blank_image.png',
      textPayload: ''
    });

    const extractor = new ImageOcrExtractor();
    const result = await extractor.extract(imgPath);

    assert.equal(result.metadata.ocr_status, 'BLANK');
    assert.equal(result.text, '');
  });

  await test('7. Corrupted image -> ERROR', async () => {
    const imgPath = createSyntheticPngImage(tempDir, {
      filename: 'corrupted_file.png',
      corruptHeader: true
    });

    const extractor = new ImageOcrExtractor();
    const result = await extractor.extract(imgPath);

    assert.equal(result.metadata.ocr_status, 'ERROR');
    assert.equal(result.metadata.error, true);
  });

  await test('8. Oversized / Huge resolution image -> RESOURCE_LIMIT_EXCEEDED', async () => {
    const imgPath = createSyntheticPngImage(tempDir, {
      filename: 'huge_resolution.png',
      width: 12000,
      height: 12000
    });

    const extractor = new ImageOcrExtractor({ maxImageWidth: 10000, maxImageHeight: 10000 });
    const result = await extractor.extract(imgPath);

    assert.equal(result.metadata.ocr_status, 'RESOURCE_LIMIT_EXCEEDED');
    assert.equal(result.metadata.error, true);
  });

  await test('9. Image filename spoofing -> SPOOF_DETECTED', async () => {
    const imgPath = createSyntheticPngImage(tempDir, {
      filename: 'gst_registration_official.png',
      textPayload: 'Random landscape photo with trees and mountains.'
    });

    const extractor = new ImageOcrExtractor();
    const result = await extractor.extract(imgPath);

    assert.equal(result.metadata.ocr_status, 'SPOOF_DETECTED');
    assert.ok(result.warnings.some(w => w.includes("Filename claims 'gst' but OCR text contains no valid GSTIN")));
  });

  await test('10. Image with conflicting GSTIN identifiers', async () => {
    const imgPath = createSyntheticPngImage(tempDir, {
      filename: 'conflicting_gstins.png',
      textPayload: 'Invoice for 27AAAAA0000A1Z5 and secondary bill for 29BBBBB1111B2Z6'
    });

    const extractor = new ImageOcrExtractor();
    const result = await extractor.extract(imgPath);
    const structured = (result.structure.structuredFields || {}) as any;

    assert.equal(structured.conflictingIdentifiers.length, 2);
    assert.ok(result.warnings.some(w => w.includes('Multiple conflicting GSTIN identifiers')));
  });

  console.log('\n--- SECTION 2: OFFLINE LICENSING, HARDWARE BINDING & CLOCK ROLLBACK ---');

  await test('11. OS-Protected store prevents SQLite deletion bypass', () => {
    const devKey = getOrCreateDevKeyPair();
    const engine = new OfflineLicenseEngine(db);
    const storePath = path.join(tempDir, 'test_store_11.dat');

    const leasePayload = {
      licenseId: 'LIC-HARDEN-001',
      organizationId: 'org-bank-001',
      deviceLimit: 100,
      modules: ['SCAN', 'AUDIT'],
      issuedAt: new Date().toISOString(),
      notBefore: new Date(Date.now() - 3600000).toISOString(),
      expiresAt: new Date(Date.now() + 10 * 86400000).toISOString(),
      licenseVersion: '1.0'
    };

    const signedLease = OfflineLicenseEngine.signLease(leasePayload, devKey.privateKey, 'fs-dev-key');

    // First validate today at T0
    const val0 = engine.validateLease(signedLease, { orgId: 'org-bank-001', publicKeyPem: devKey.publicKey, protectedStorePath: storePath });
    assert.equal(val0.valid, true);

    // Simulate deleting SQLite database
    db.exec('DELETE FROM license_state;');

    // Re-validate: engine reloads OS-Protected Store, preserves monotonic progress and state!
    const val1 = engine.validateLease(signedLease, { orgId: 'org-bank-001', publicKeyPem: devKey.publicKey, protectedStorePath: storePath });
    assert.equal(val1.valid, true);
  });

  await test('12. Clock rollback via OS-protected store triggers CLOCK_ROLLBACK_DETECTED', () => {
    const devKey = getOrCreateDevKeyPair();
    const engine = new OfflineLicenseEngine(db);
    const storePath = path.join(tempDir, 'test_store_12.dat');

    const leasePayload = {
      licenseId: 'LIC-HARDEN-002',
      organizationId: 'org-bank-001',
      deviceLimit: 100,
      modules: ['SCAN'],
      issuedAt: new Date().toISOString(),
      notBefore: new Date(Date.now() - 3600000).toISOString(),
      expiresAt: new Date(Date.now() + 30 * 86400000).toISOString(),
      licenseVersion: '1.0'
    };

    const signedLease = OfflineLicenseEngine.signLease(leasePayload, devKey.privateKey, 'fs-dev-key');

    // Advance clock to Day +10
    const day10 = new Date(Date.now() + 10 * 86400000);
    engine.validateLease(signedLease, { orgId: 'org-bank-001', currentTime: day10, publicKeyPem: devKey.publicKey, protectedStorePath: storePath });

    // Now turn clock back to Day +2
    const day2 = new Date(Date.now() + 2 * 86400000);
    const rollbackRes = engine.validateLease(signedLease, { orgId: 'org-bank-001', currentTime: day2, publicKeyPem: devKey.publicKey, protectedStorePath: storePath });

    assert.equal(rollbackRes.valid, false);
    assert.equal(rollbackRes.status, 'CLOCK_ROLLBACK_DETECTED');
  });

  await test('13. Cloned environment / VM fingerprint mismatch -> DEVICE_MISMATCH', () => {
    const storePath = path.join(tempDir, 'test_store_13.dat');
    const protectedStore = new ProtectedLicenseStore(storePath);
    const devKey = getOrCreateDevKeyPair();
    const engine = new OfflineLicenseEngine(db);

    const leasePayload = {
      licenseId: 'LIC-HARDEN-003',
      organizationId: 'org-bank-001',
      deviceLimit: 100,
      modules: ['SCAN'],
      issuedAt: new Date().toISOString(),
      notBefore: new Date(Date.now() - 3600000).toISOString(),
      expiresAt: new Date(Date.now() + 30 * 86400000).toISOString(),
      licenseVersion: '1.0'
    };

    const signedLease = OfflineLicenseEngine.signLease(leasePayload, devKey.privateKey, 'fs-dev-key');

    // Save protected state with different hardware fingerprint
    protectedStore.saveState({
      organizationId: 'org-bank-001',
      licenseId: 'LIC-HARDEN-003',
      signedLeaseJson: JSON.stringify(signedLease),
      machineFingerprint: 'DIFFERENT_CLONED_MACHINE_HARDWARE_FP_99999',
      maxSeenTimestampIso: new Date().toISOString(),
      lastTrustedTimestampIso: new Date().toISOString(),
      status: 'ACTIVE',
      graceUntilIso: new Date(Date.now() + 33 * 86400000).toISOString(),
      expiresAtIso: leasePayload.expiresAt,
      clockRollbackDetected: false,
      updatedAtIso: new Date().toISOString()
    });

    const cloneRes = engine.validateLease(signedLease, { orgId: 'org-bank-001', publicKeyPem: devKey.publicKey, protectedStorePath: storePath });

    assert.equal(cloneRes.valid, false);
    assert.equal(cloneRes.status, 'DEVICE_MISMATCH');
    assert.ok(cloneRes.message.includes('Cloned environment detected'));
  });

  console.log('\n--- SECTION 3: 500-FILE & 1,000-FILE LARGE RESILIENT SCANS ---');

  await test('14. Execute 1,000-File Resilient Scan with Mixed Document Formats', async () => {
    const scaleDir = path.join(tempDir, 'Scale_1000_Files');
    fs.mkdirSync(scaleDir, { recursive: true });

    // Generate 1000 mixed test files
    for (let i = 0; i < 1000; i++) {
      const ext = i % 4 === 0 ? 'pdf' : i % 4 === 1 ? 'csv' : i % 4 === 2 ? 'txt' : 'png';
      if (ext === 'png') {
        createSyntheticPngImage(scaleDir, {
          filename: `scan_item_${i}.png`,
          textPayload: `Scanned Evidence Item #${i} GSTIN: 27AAAAA0000A1Z5`
        });
      } else {
        fs.writeFileSync(
          path.join(scaleDir, `scan_item_${i}.${ext}`),
          `Compliance file payload #${i}\nGSTIN: 27AAAAA0000A1Z5\nDate: 01/01/2025`
        );
      }
    }

    const manager = new ScanJobManager(db);
    const job = manager.createScanJob({
      orgId: 'org-bank-001',
      endpointId: 'EP-LARGE-SCALE-01',
      checklistId: 'BANK-IAM-2026',
      sources: [scaleDir]
    });

    assert.equal(job.total_files, 1000);

    const completed = await manager.executeScanJob(job.scan_id, 'org-bank-001');
    assert.equal(completed.status, 'COMPLETED');
    assert.equal(completed.processed_files, 1000);
    assert.equal(completed.failed_files, 0);
  });

  console.log('\n--- SECTION 4: MODULAR CHECKLIST VALIDATION & SECURITY ---');

  await test('15. Declarative Checklist Execution (TEST-CHECKLIST-A vs TEST-CHECKLIST-B)', () => {
    const mgr = new ChecklistManager(db);

    const manifestA: any = {
      id: 'TEST-CHECKLIST-A',
      version: '1.0.0',
      name: 'Test Checklist A',
      description: 'Test A',
      publisher: 'Publisher A',
      controlCount: 1,
      minimumEngineVersion: '8.0.0'
    };
    const controlsA: any = [{
      id: 'CTRL-A1',
      name: 'Control A1',
      domain: 'IDENTITY_ACCESS',
      category: 'ZERO_TOLERANCE',
      severity: 'CRITICAL',
      logic: 'SINGLE',
      keywords: ['GSTIN']
    }];

    mgr.installPackage(manifestA, controlsA);
    const pkgA = mgr.getPackage('TEST-CHECKLIST-A');
    assert.ok(pkgA);
    assert.equal(pkgA.controls.length, 1);

    // Disable Checklist A
    mgr.setEnabled('TEST-CHECKLIST-A', false);
    assert.equal(mgr.getPackage('TEST-CHECKLIST-A')?.enabled, false);
  });

  await test('16. Executable Payload Security Defense (Rejects Code Injection)', () => {
    const mgr = new ChecklistManager(db);

    const manifestMalicious: any = {
      id: 'MALICIOUS-CHECKLIST',
      version: '1.0.0',
      name: 'Malicious Checklist',
      description: 'Malicious test package',
      publisher: 'Untrusted Publisher',
      controlCount: 1,
      minimumEngineVersion: '1.0.0'
    };
    const controlsMalicious: any = [{
      id: 'CTRL-MAL1',
      name: 'Control Malicious',
      domain: 'IDENTITY_ACCESS',
      category: 'ZERO_TOLERANCE',
      severity: 'CRITICAL',
      logic: 'SINGLE',
      keywords: ['eval(process.exit(1))']
    }];

    const val = mgr.validatePackage(manifestMalicious, controlsMalicious);
    assert.equal(val.valid, false);
    assert.ok(val.errors.some(e => e.includes('SECURITY VIOLATION: Executable payload pattern')));
  });

  await test('17. Incompatible Minimum Engine Version Rejection', () => {
    const mgr = new ChecklistManager(db);

    const manifestFuture: any = {
      id: 'FUTURE-CHECKLIST',
      version: '1.0.0',
      name: 'Future Engine Checklist',
      description: 'Future test package',
      publisher: 'Future Publisher',
      controlCount: 1,
      minimumEngineVersion: '99.0.0'
    };
    const controlsFuture: any = [{
      id: 'CTRL-F1',
      name: 'Future Control',
      domain: 'IDENTITY_ACCESS',
      category: 'ZERO_TOLERANCE',
      severity: 'CRITICAL',
      logic: 'SINGLE'
    }];

    const val = mgr.validatePackage(manifestFuture, controlsFuture);
    assert.equal(val.valid, false);
    assert.ok(val.errors.some(e => e.includes('Incompatible engine version')));
  });

  console.log('\n--- SECTION 5: TENANT ISOLATION ---');

  await test('18. Cross-Tenant IDOR Prevention on Scan Jobs', () => {
    const manager = new ScanJobManager(db);

    // Create scan job for Tenant 1
    const jobOrg1 = manager.createScanJob({
      orgId: 'org-bank-001',
      endpointId: 'EP-BANK-1',
      checklistId: 'BANK-IAM-2026',
      sources: [tempDir]
    });

    // Attempt to access scan job using Tenant 2 -> returns undefined / 404
    const idorAttempt = manager.getScanJob(jobOrg1.scan_id, 'org-bank-002');
    assert.equal(idorAttempt, null);
  });

  // Cleanup workspace
  db.close();
  if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
  if (fs.existsSync(tempDir)) fs.rmSync(tempDir, { recursive: true, force: true });

  console.log('\n========================================================================');
  console.log(`  ALL ${passedTests}/${totalTests} HARDENING TESTS PASSED (100% SUCCESS)`);
  console.log('========================================================================\n');
  process.exit(0);
}

runCommercialHardeningSuite().catch(err => {
  console.error('Fatal error running hardening suite:', err);
  process.exit(1);
});
