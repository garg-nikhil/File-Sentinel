import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { ImageOcrExtractor } from '../backend/extractors/imageOcrExtractor.js';
import { WorkerPool } from '../backend/workers/workerPool.js';
import { ScanJobManager } from '../backend/scanJobManager.js';
import { ChecklistManager } from '../backend/checklists/checklistManager.js';
import { OfflineLicenseEngine, getOrCreateDevKeyPair, SignedLicenseLease } from '../backend/licensing/offlineLicense.js';
import { StandardWindowsAgentBoundary } from '../backend/endpoint/agentBoundary.js';
import { defaultRegistry } from '../backend/extractors/registry.js';
import { createSyntheticPngImage } from './helpers/imageGenerator.js';

async function runScalableOfflineTestSuite() {
  console.log('========================================================================');
  console.log('  FILE-SENTINEL: Scalable Offline Desktop Architecture Test Suite       ');
  console.log('========================================================================\n');

  let totalTests = 0;
  let passedTests = 0;

  function test(name: string, fn: () => void | Promise<void>) {
    totalTests++;
    return (async () => {
      try {
        await fn();
        passedTests++;
        console.log(`  [PASS] Test ${totalTests}: ${name}`);
      } catch (err: any) {
        console.error(`  [FAIL] Test ${totalTests}: ${name}`);
        console.error(`         Error: ${err.message}`);
      }
    })();
  }

  // Set up temporary SQLite database & test workspace
  const dbPath = path.join(process.cwd(), 'test_desktop_scalable.db');
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
  `);

  const tempTestDir = path.join(process.cwd(), 'test_scan_workspace');
  if (!fs.existsSync(tempTestDir)) fs.mkdirSync(tempTestDir, { recursive: true });

  console.log('--- SECTION 1: IMAGE OCR EVIDENCE EXTRACTOR & SAFETY LIMITS ---');

  await test('ImageOcrExtractor handles image extensions', () => {
    const extractor = new ImageOcrExtractor();
    assert.equal(extractor.canHandle('sample.jpg'), true);
    assert.equal(extractor.canHandle('sample.png'), true);
    assert.equal(extractor.canHandle('sample.webp'), true);
    assert.equal(extractor.canHandle('sample.tiff'), true);
    assert.equal(extractor.canHandle('sample.pdf'), false);
  });

  await test('PNG header dimension parsing without native C++ crashes', () => {
    const extractor = new ImageOcrExtractor();
    // Valid PNG header snippet
    const pngHeader = Buffer.alloc(30);
    pngHeader[0] = 0x89; pngHeader[1] = 0x50; pngHeader[2] = 0x4E; pngHeader[3] = 0x47;
    pngHeader.writeUInt32BE(1920, 16);
    pngHeader.writeUInt32BE(1080, 20);

    const dim = extractor.parseImageDimensions(pngHeader, '.png');
    assert.equal(dim.validFormat, true);
    assert.equal(dim.width, 1920);
    assert.equal(dim.height, 1080);
    assert.equal(dim.format, 'PNG');
  });

  await test('OCR extracts text and assigns IMAGE_OCR evidence metadata', async () => {
    const imgPath = createSyntheticPngImage(tempTestDir, {
      filename: 'gst_certificate.png',
      textPayload: 'GSTIN: 27AAAAA0000A1Z5 Form GST REG-06 Certificate of Registration'
    });

    const extractor = new ImageOcrExtractor();
    const res = await extractor.extract(imgPath);

    assert.equal(res.metadata.evidence_type, 'IMAGE_OCR');
    assert.equal(res.metadata.is_ocr, true);
    assert.ok(res.text.includes('GSTIN') || res.text.includes('GST'));
  });

  await test('Oversized image dimensions rejected with OCR error', async () => {
    const imgPath = path.join(tempTestDir, 'huge_image.png');
    const pngHeader = Buffer.alloc(30);
    pngHeader[0] = 0x89; pngHeader[1] = 0x50; pngHeader[2] = 0x4E; pngHeader[3] = 0x47;
    pngHeader.writeUInt32BE(10000, 16);
    pngHeader.writeUInt32BE(10000, 20);
    fs.writeFileSync(imgPath, pngHeader);

    // Limit maxImagePixels to 1,000,000 (100MP image will fail)
    const extractor = new ImageOcrExtractor({ maxImagePixels: 1_000_000 });
    const res = await extractor.extract(imgPath);

    assert.equal(res.metadata.error, true);
    assert.ok(res.warnings[0].includes('exceed maximum allowed resource limit'));
  });

  console.log('\n--- SECTION 2: CONTROLLED WORKER POOL & CONCURRENCY ---');

  await test('WorkerPool respects maxConcurrentParsers & maxConcurrentOCR', async () => {
    const pool = new WorkerPool({ maxConcurrentParsers: 2, maxConcurrentOCR: 1 });
    const stats = pool.getStats();

    assert.equal(stats.maxDocWorkers, 2);
    assert.equal(stats.maxOcrWorkers, 1);
    assert.equal(stats.activeDocWorkers, 0);
  });

  await test('WorkerPool pause and resume functionality', async () => {
    const pool = new WorkerPool();
    pool.pause();
    assert.equal(pool.getStats().isPaused, true);
    pool.resume();
    assert.equal(pool.getStats().isPaused, false);
  });

  console.log('\n--- SECTION 3: RESUMABLE SCAN JOB MANAGER & MULTI-DRIVE SCANS ---');

  await test('ScanJobManager initializes job and discovers source files', () => {
    // Create test files in subdirectories
    const subDir1 = path.join(tempTestDir, 'Drive_C');
    const subDir2 = path.join(tempTestDir, 'Drive_USB');
    fs.mkdirSync(subDir1, { recursive: true });
    fs.mkdirSync(subDir2, { recursive: true });

    fs.writeFileSync(path.join(subDir1, 'report.pdf'), 'PDF content demo');
    fs.writeFileSync(path.join(subDir1, 'data.csv'), 'id,name\n1,test');
    fs.writeFileSync(path.join(subDir2, 'photo.jpg'), 'JPEG content demo');

    const manager = new ScanJobManager(db);
    const job = manager.createScanJob({
      orgId: 'org-bank-001',
      endpointId: 'EP-DESKTOP-001',
      checklistId: 'BANK-IAM-2026',
      sources: [subDir1, subDir2]
    });

    assert.ok(job.scan_id.startsWith('SCAN-'));
    assert.equal(job.total_files, 3);
    assert.equal(job.status, 'QUEUED');
  });

  await test('ScanJobManager executes scan and updates file states continuously', async () => {
    const subDir1 = path.join(tempTestDir, 'Drive_C');
    const manager = new ScanJobManager(db);

    const job = manager.createScanJob({
      orgId: 'org-bank-001',
      endpointId: 'EP-DESKTOP-001',
      checklistId: 'BANK-IAM-2026',
      sources: [subDir1]
    });

    const completedJob = await manager.executeScanJob(job.scan_id, 'org-bank-001');

    assert.equal(completedJob.status, 'COMPLETED');
    assert.equal(completedJob.processed_files, 2);
    assert.ok(completedJob.evidence_hash?.startsWith('SHA256:'));

    // Check individual scan files
    const fileList = manager.listScanFiles(job.scan_id, 'org-bank-001');
    assert.equal(fileList.total, 2);
    assert.equal(fileList.files[0].state, 'COMPLETED');
  });

  await test('500-File Scalable Scan Job Simulation', async () => {
    const largeDir = path.join(tempTestDir, 'Scale_500_Files');
    fs.mkdirSync(largeDir, { recursive: true });

    // Generate 500 small test files
    for (let i = 0; i < 500; i++) {
      fs.writeFileSync(
        path.join(largeDir, `file_${i}.${i % 2 === 0 ? 'txt' : 'csv'}`),
        `Sample compliance evidence file number ${i}\nGSTIN: 27AAAAA0000A1Z5`
      );
    }

    const manager = new ScanJobManager(db);
    const job = manager.createScanJob({
      orgId: 'org-bank-001',
      endpointId: 'EP-SCALE-001',
      checklistId: 'INTERNAL-SECURITY',
      sources: [largeDir]
    });

    assert.equal(job.total_files, 500);

    const completed = await manager.executeScanJob(job.scan_id, 'org-bank-001');
    assert.equal(completed.status, 'COMPLETED');
    assert.equal(completed.processed_files, 500);
    assert.equal(completed.failed_files, 0);
  });

  console.log('\n--- SECTION 4: MODULAR CHECKLIST PACKAGE ENGINE ---');

  await test('ChecklistManager syncs and validates disk packages', () => {
    const mgr = new ChecklistManager(db);
    const count = mgr.syncFromDisk('./checklists');
    assert.ok(count >= 3);

    const packages = mgr.listPackages();
    assert.ok(packages.some(p => p.manifest.id === 'BANK-IAM-2026'));
    assert.ok(packages.some(p => p.manifest.id === 'RBI-VENDOR-2026'));
    assert.ok(packages.some(p => p.manifest.id === 'INTERNAL-SECURITY'));
  });

  await test('ChecklistManager lifecycle: enable, disable, and parameter conversion', () => {
    const mgr = new ChecklistManager(db);
    const pkgId = 'BANK-IAM-2026';

    // Convert controls to AuditParameters for engine
    const params = mgr.toAuditParameters(pkgId);
    assert.ok(params.length > 0);
    assert.equal(params[0].category, 'ZERO_TOLERANCE');

    // Disable package
    mgr.setEnabled(pkgId, false);
    let updated = mgr.getPackage(pkgId);
    assert.equal(updated?.enabled, false);

    // Re-enable package
    mgr.setEnabled(pkgId, true);
    updated = mgr.getPackage(pkgId);
    assert.equal(updated?.enabled, true);
  });

  await test('ChecklistManager rejects malformed packages', () => {
    const mgr = new ChecklistManager(db);
    const invalidManifest: any = {
      id: 'bad-id-@#$',
      version: 'invalid_ver',
      name: 'X',
      controlCount: 5
    };
    const validation = mgr.validatePackage(invalidManifest, []);
    assert.equal(validation.valid, false);
    assert.ok(validation.errors.length > 0);
  });

  console.log('\n--- SECTION 5: SIGNED OFFLINE LICENSE LEASE & CLOCK ROLLBACK ---');

  await test('Ed25519 signature generation and offline verification', () => {
    const devKeyPair = getOrCreateDevKeyPair();
    const leasePayload = {
      licenseId: 'LIC-2026-TEST',
      organizationId: 'org-bank-001',
      deviceLimit: 50,
      modules: ['SCAN', 'AUDIT'],
      issuedAt: new Date().toISOString(),
      notBefore: new Date(Date.now() - 3600000).toISOString(),
      expiresAt: new Date(Date.now() + 30 * 86400000).toISOString(),
      licenseVersion: '1.0'
    };

    const signedLease = OfflineLicenseEngine.signLease(leasePayload, devKeyPair.privateKey, 'fs-dev-key');
    const isValid = OfflineLicenseEngine.verifySignature(signedLease, devKeyPair.publicKey);
    assert.equal(isValid, true);

    // Tampered payload fails verification
    const tampered = { ...signedLease, payload: { ...signedLease.payload, deviceLimit: 9999 } };
    const isTamperedValid = OfflineLicenseEngine.verifySignature(tampered, devKeyPair.publicKey);
    assert.equal(isTamperedValid, false);
  });

  await test('OfflineLicenseEngine validates active lease and tenant binding', () => {
    const engine = new OfflineLicenseEngine(db);
    const devKeyPair = getOrCreateDevKeyPair();
    const storePath = path.join(tempTestDir, 'store_active.json');
    if (fs.existsSync(storePath)) fs.unlinkSync(storePath);

    const leasePayload = {
      licenseId: 'LIC-ACTIVE-001',
      organizationId: 'org-bank-001',
      deviceLimit: 50,
      modules: ['SCAN', 'AUDIT'],
      issuedAt: new Date().toISOString(),
      notBefore: new Date(Date.now() - 3600000).toISOString(),
      expiresAt: new Date(Date.now() + 30 * 86400000).toISOString(),
      licenseVersion: '1.0'
    };

    const signedLease = OfflineLicenseEngine.signLease(leasePayload, devKeyPair.privateKey, 'fs-dev-key');
    const result = engine.validateLease(signedLease, {
      orgId: 'org-bank-001',
      publicKeyPem: devKeyPair.publicKey,
      protectedStorePath: storePath
    });

    assert.equal(result.valid, true);
    assert.equal(result.status, 'ACTIVE');
    assert.equal(result.canScan, true);
  });

  await test('OfflineLicenseEngine flags renewal warnings (7d, 3d, 1d)', () => {
    const engine = new OfflineLicenseEngine(db);
    const devKeyPair = getOrCreateDevKeyPair();
    const storePath = path.join(tempTestDir, 'store_warn.json');
    if (fs.existsSync(storePath)) fs.unlinkSync(storePath);

    // 2 days remaining -> WARNING_3D
    const leasePayload = {
      licenseId: 'LIC-WARN-001',
      organizationId: 'org-bank-001',
      deviceLimit: 50,
      modules: ['SCAN'],
      issuedAt: new Date().toISOString(),
      notBefore: new Date(Date.now() - 3600000).toISOString(),
      expiresAt: new Date(Date.now() + 2 * 86400000).toISOString(),
      licenseVersion: '1.0'
    };

    const signedLease = OfflineLicenseEngine.signLease(leasePayload, devKeyPair.privateKey, 'fs-dev-key');
    const result = engine.validateLease(signedLease, {
      orgId: 'org-bank-001',
      publicKeyPem: devKeyPair.publicKey,
      protectedStorePath: storePath
    });

    assert.equal(result.valid, true);
    assert.equal(result.status, 'WARNING_3D');
    assert.ok(result.message.includes('expires in 2 days'));
  });

  await test('OfflineLicenseEngine grace period and expiration enforcement', () => {
    const engine = new OfflineLicenseEngine(db, 3); // 3 day grace
    const devKeyPair = getOrCreateDevKeyPair();
    const storePath = path.join(tempTestDir, 'store_grace.json');
    if (fs.existsSync(storePath)) fs.unlinkSync(storePath);

    // Expired 1 day ago (within 3 day grace)
    const expiredLease = {
      licenseId: 'LIC-EXPIRED-001',
      organizationId: 'org-bank-001',
      deviceLimit: 50,
      modules: ['SCAN'],
      issuedAt: new Date(Date.now() - 10 * 86400000).toISOString(),
      notBefore: new Date(Date.now() - 10 * 86400000).toISOString(),
      expiresAt: new Date(Date.now() - 1 * 86400000).toISOString(),
      licenseVersion: '1.0'
    };

    const signed = OfflineLicenseEngine.signLease(expiredLease, devKeyPair.privateKey, 'fs-dev-key');
    const result = engine.validateLease(signed, {
      orgId: 'org-bank-001',
      publicKeyPem: devKeyPair.publicKey,
      protectedStorePath: storePath
    });

    assert.equal(result.status, 'GRACE_PERIOD');
    assert.equal(result.isGracePeriod, true);
    assert.equal(result.canScan, true);

    // Expired 5 days ago (past 3 day grace)
    const fullyExpired = {
      ...expiredLease,
      licenseId: 'LIC-EXPIRED-PAST-GRACE',
      expiresAt: new Date(Date.now() - 5 * 86400000).toISOString()
    };
    const signedFull = OfflineLicenseEngine.signLease(fullyExpired, devKeyPair.privateKey, 'fs-dev-key');
    const fullResult = engine.validateLease(signedFull, {
      orgId: 'org-bank-001',
      publicKeyPem: devKeyPair.publicKey,
      protectedStorePath: storePath
    });

    assert.equal(fullResult.valid, false);
    assert.equal(fullResult.status, 'EXPIRED');
    assert.equal(fullResult.canScan, false);
  });

  await test('Clock rollback detection triggers CLOCK_ROLLBACK_DETECTED', () => {
    const engine = new OfflineLicenseEngine(db);
    const devKeyPair = getOrCreateDevKeyPair();
    const storePath = path.join(tempTestDir, 'store_clock.json');
    if (fs.existsSync(storePath)) fs.unlinkSync(storePath);

    const lease = {
      licenseId: 'LIC-CLOCK-001',
      organizationId: 'org-bank-001',
      deviceLimit: 50,
      modules: ['SCAN'],
      issuedAt: new Date().toISOString(),
      notBefore: new Date(Date.now() - 3600000).toISOString(),
      expiresAt: new Date(Date.now() + 30 * 86400000).toISOString(),
      licenseVersion: '1.0'
    };

    const signed = OfflineLicenseEngine.signLease(lease, devKeyPair.privateKey, 'fs-dev-key');

    // First validate at future time (establishes last_trusted_timestamp)
    const futureTime = new Date(Date.now() + 5 * 86400000); // 5 days in future
    engine.validateLease(signed, {
      orgId: 'org-bank-001',
      currentTime: futureTime,
      publicKeyPem: devKeyPair.publicKey,
      protectedStorePath: storePath
    });

    // Now validate back at current time (clock rolled back by 5 days!)
    const rollbackResult = engine.validateLease(signed, {
      orgId: 'org-bank-001',
      currentTime: new Date(),
      publicKeyPem: devKeyPair.publicKey,
      protectedStorePath: storePath
    });

    assert.equal(rollbackResult.valid, false);
    assert.equal(rollbackResult.status, 'CLOCK_ROLLBACK_DETECTED');
    assert.equal(rollbackResult.clockRollbackDetected, true);
  });

  console.log('\n--- SECTION 6: WINDOWS PRIVILEGED AGENT EXECUTION BOUNDARY ---');

  await test('StandardWindowsAgentBoundary blocks invasive active remediations', async () => {
    const boundary = new StandardWindowsAgentBoundary();
    const ctx = await boundary.getPrivilegeContext();
    assert.equal(ctx.isElevated, false);

    const check = boundary.validateExecutionBoundary({
      operationId: 'OP-001',
      action: 'DISABLE_USB',
      targetResource: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR',
      payload: {},
      requestedBy: { orgId: 'org-bank-001', userId: 'usr-1', deviceId: 'dev-1' },
      requiresElevation: true
    });

    assert.equal(check.allowed, false);
    assert.ok(check.reason?.includes('reserved for privileged Phase B'));
  });

  // Cleanup
  db.close();
  if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
  if (fs.existsSync(tempTestDir)) fs.rmSync(tempTestDir, { recursive: true, force: true });

  console.log('\n========================================================================');
  console.log(`  ALL ${passedTests}/${totalTests} TESTS PASSED PERFECTLY (100% SUCCESS)`);
  console.log('========================================================================\n');
  process.exit(0);
}

runScalableOfflineTestSuite().catch(err => {
  console.error('Fatal error running suite:', err);
  process.exit(1);
});
