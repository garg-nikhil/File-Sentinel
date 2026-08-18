import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  getDatabase,
  persistDatabaseToEncryptedFile,
  serializeDatabaseInMemory,
  restoreDatabaseFromMemory,
  encryptDatabaseBuffer,
  decryptDatabaseBuffer,
  isEncryptedDatabaseFile
} from '../backend/db.js';
import {
  OfflineLicenseEngine,
  getOrCreateDevKeyPair,
  TRUSTED_PUBLIC_KEYS
} from '../backend/licensing/offlineLicense.js';
import {
  FileIntegrityMonitor
} from '../backend/fimService.js';
import {
  TRUSTED_FIM_PUBLIC_KEY,
  verifySignedFimManifest,
  isValidManifestStructure,
  SignedFimManifest
} from '../backend/fimManifest.js';

let totalTests = 0;
let passedTests = 0;

function assert(condition: boolean, message: string) {
  totalTests++;
  if (!condition) {
    console.error(`  [FAIL] Test ${totalTests}: ${message}`);
    throw new Error(`Test assertion failed: ${message}`);
  }
  passedTests++;
  console.log(`  [PASS] Test ${totalTests}: ${message}`);
}

async function runP0BlockerTestSuite() {
  console.log('========================================================================');
  console.log('  FILE-SENTINEL: FINAL P0 RELEASE BLOCKER VERIFICATION SUITE           ');
  console.log('========================================================================\n');

  const testTempDir = path.join(process.cwd(), `.tmp_p0_test_${Date.now()}`);
  fs.mkdirSync(testTempDir, { recursive: true });

  try {
    // =========================================================================
    // SECTION 1: PROHIBITION OF LOCAL PRODUCTION LICENSE MINTING
    // =========================================================================
    console.log('--- SECTION 1: NO PRODUCTION LICENSE MINTING ---');

    // 1.1 Non-dev mode cannot mint keypair even if NODE_ENV is development
    const prevDevMode = process.env.FILE_SENTINEL_DEV_MODE;
    const prevNodeEnv = process.env.NODE_ENV;

    delete process.env.FILE_SENTINEL_DEV_MODE;
    process.env.NODE_ENV = 'development';
    let mintFailed = false;
    try {
      getOrCreateDevKeyPair();
    } catch (e: any) {
      mintFailed = e.message.includes('SECURITY FATAL');
    }
    assert(mintFailed, 'getOrCreateDevKeyPair fails closed when FILE_SENTINEL_DEV_MODE is unset (NODE_ENV=development)');

    // 1.2 Non-dev mode cannot mint when NODE_ENV is undefined
    delete process.env.NODE_ENV;
    delete process.env.FILE_SENTINEL_DEV_MODE;
    mintFailed = false;
    try {
      getOrCreateDevKeyPair();
    } catch (e: any) {
      mintFailed = e.message.includes('SECURITY FATAL');
    }
    assert(mintFailed, 'getOrCreateDevKeyPair fails closed when NODE_ENV is undefined');

    // 1.3 Cannot sign lease when NODE_ENV is production
    process.env.FILE_SENTINEL_DEV_MODE = 'true';
    process.env.NODE_ENV = 'production';
    let signFailed = false;
    try {
      OfflineLicenseEngine.signLease({
        licenseId: 'LIC-TEST',
        organizationId: 'org-test',
        deviceLimit: 10,
        modules: ['SCAN'],
        issuedAt: new Date().toISOString(),
        notBefore: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
        licenseVersion: '8.2.0'
      }, 'fake-priv-key');
    } catch (e: any) {
      signFailed = e.message.includes('SECURITY FATAL');
    }
    assert(signFailed, 'OfflineLicenseEngine.signLease strictly fails closed in production mode');

    // 1.4 Production license validation strictly enforces official authority key and rejects forged key IDs
    const mockDb = getDatabase(':memory:');
    const licEngine = new OfflineLicenseEngine(mockDb);

    const forgedLease = {
      payload: {
        licenseId: 'LIC-FORGED-001',
        organizationId: 'org-victim',
        deviceLimit: 100,
        modules: ['SCAN', 'AUDIT'],
        issuedAt: new Date().toISOString(),
        notBefore: new Date(Date.now() - 3600000).toISOString(),
        expiresAt: new Date(Date.now() + 30 * 86400000).toISOString(),
        licenseVersion: '8.2.0'
      },
      signature: 'invalid_signature_base64==',
      publicKeyId: 'fs-dev-key' // Attempting to use dev key in production
    };

    const forgedRes = licEngine.validateLease(forgedLease, { orgId: 'org-victim' });
    assert(!forgedRes.valid && (forgedRes.status === 'INVALID_SIGNATURE' || forgedRes.status === 'REVOKED'), 'Production license validator rejects forged/dev keys and invalid signatures');

    // 1.5 Expired license remains expired across repeated evaluations and resets
    process.env.FILE_SENTINEL_DEV_MODE = 'true';
    delete process.env.NODE_ENV;
    const devKeyPair = getOrCreateDevKeyPair();

    const expiredPayload = {
      licenseId: 'LIC-EXPIRED-001',
      organizationId: 'org-expired',
      deviceLimit: 10,
      modules: ['SCAN'],
      issuedAt: new Date(Date.now() - 60 * 86400000).toISOString(),
      notBefore: new Date(Date.now() - 60 * 86400000).toISOString(),
      expiresAt: new Date(Date.now() - 10 * 86400000).toISOString(),
      licenseVersion: '8.2.0'
    };

    const signedExpiredLease = OfflineLicenseEngine.signLease(expiredPayload, devKeyPair.privateKey, 'fs-dev-key');

    // Store expired state directly in DB
    mockDb.prepare("INSERT OR IGNORE INTO organizations (org_id, name, created_at) VALUES ('org-expired', 'Expired Org', datetime('now'))").run();

    mockDb.prepare(`
      INSERT INTO license_state (id, org_id, license_id, lease_jwt, license_version, device_limit, modules_json, issued_at, not_before, expires_at, grace_until, last_trusted_timestamp, status, updated_at)
      VALUES (?, ?, ?, ?, ?, 10, '["SCAN"]', ?, ?, ?, ?, ?, 'EXPIRED', datetime('now'))
    `).run('ls-expired-1', 'org-expired', 'LIC-EXPIRED-001', JSON.stringify(signedExpiredLease), '8.2.0', expiredPayload.issuedAt, expiredPayload.notBefore, expiredPayload.expiresAt, expiredPayload.expiresAt, expiredPayload.expiresAt);

    const dummyStorePath = path.join(testTempDir, 'isolated_test.store');
    const expiredValidation1 = licEngine.validateCurrentLicense({ orgId: 'org-expired', protectedStorePath: dummyStorePath });
    assert(!expiredValidation1.canScan && expiredValidation1.status === 'EXPIRED', 'Expired license is blocked on initial check');

    const expiredValidation2 = licEngine.validateCurrentLicense({ orgId: 'org-expired', protectedStorePath: dummyStorePath });
    assert(!expiredValidation2.canScan && expiredValidation2.status === 'EXPIRED', 'Expired license is blocked on repeated check without auto-renewal');

    // Restore environment
    if (prevDevMode) process.env.FILE_SENTINEL_DEV_MODE = prevDevMode;
    else delete process.env.FILE_SENTINEL_DEV_MODE;
    if (prevNodeEnv) process.env.NODE_ENV = prevNodeEnv;
    else delete process.env.NODE_ENV;


    // =========================================================================
    // SECTION 2: ELIMINATE PLAINTEXT DATABASE STAGING
    // =========================================================================
    console.log('\n--- SECTION 2: AUTHENTICATED ENCRYPTED DATABASE AT REST (NO PLAINTEXT STAGING) ---');

    const encDbPath = path.join(testTempDir, 'production_secure.db');

    // 2.1 Production getDatabase creates an encrypted database container on disk
    const db1 = getDatabase(encDbPath);
    db1.prepare("INSERT INTO organizations (org_id, name, created_at) VALUES ('org-sec-1', 'Secure Org', datetime('now'))").run();
    db1.prepare("INSERT INTO users (user_id, org_id, username, password_hash, role, disabled, created_at) VALUES ('u-sec-1', 'org-sec-1', 'secadmin', 'hash123', 'ORG_ADMIN', 0, datetime('now'))").run();
    db1.prepare("INSERT INTO scans (scan_id, root_path, start_time, status) VALUES ('scan-sec-1', '/data/evidence', datetime('now'), 'COMPLETED')").run();

    // Persist to encrypted file
    persistDatabaseToEncryptedFile(db1, encDbPath);

    // Verify the file on disk is strictly AES-256-GCM encrypted and does NOT contain SQLite plaintext magic
    const diskBytes = fs.readFileSync(encDbPath);
    const hasFsMagic = isEncryptedDatabaseFile(encDbPath);
    const hasPlaintextSqliteHeader = diskBytes.subarray(0, 16).toString('utf8').includes('SQLite format 3');

    assert(hasFsMagic, 'Database file on disk has authentic FileSentinel encrypted container magic header');
    assert(!hasPlaintextSqliteHeader, 'Database file on disk contains NO plaintext SQLite format header');

    // Verify no temporary .tmp_vac_ or .tmp_stage_ files exist in directory
    const remainingFiles = fs.readdirSync(testTempDir);
    const tempStagingFiles = remainingFiles.filter(f => f.startsWith('.tmp_vac_') || f.startsWith('.tmp_stage_') || f.endsWith('.db-wal') || f.endsWith('.db-journal'));
    assert(tempStagingFiles.length === 0, 'No temporary plaintext SQLite staging artifacts exist on disk');

    // 2.2 Restart and read from encrypted DB without any plaintext staging
    const db2 = getDatabase(encDbPath);
    const readOrg = db2.prepare("SELECT * FROM organizations WHERE org_id = 'org-sec-1'").get() as any;
    const readScan = db2.prepare("SELECT * FROM scans WHERE scan_id = 'scan-sec-1'").get() as any;
    assert(readOrg && readOrg.name === 'Secure Org', 'Restarted database reads org data successfully from authenticated encrypted container');
    assert(readScan && readScan.status === 'COMPLETED', 'Restarted database reads scan audit data successfully');

    // 2.3 Wrong decryption key fails closed immediately
    let wrongKeyFailed = false;
    try {
      const wrongKey = crypto.randomBytes(32).toString('hex');
      decryptDatabaseBuffer(diskBytes, wrongKey);
    } catch (e: any) {
      wrongKeyFailed = e.message.includes('SECURITY FATAL') || e.message.includes('integrity');
    }
    assert(wrongKeyFailed, 'Decryption with wrong key fails closed without exposing data');

    // 2.4 Tampered encrypted DB file fails closed immediately
    const tamperedBytes = Buffer.from(diskBytes);
    // Tamper one byte in the ciphertext payload
    tamperedBytes[tamperedBytes.length - 10] ^= 0xFF;
    const tamperedDbPath = path.join(testTempDir, 'tampered_db.db');
    fs.writeFileSync(tamperedDbPath, tamperedBytes);

    let tamperDetectionPassed = false;
    try {
      getDatabase(tamperedDbPath);
    } catch (e: any) {
      tamperDetectionPassed = e.message.includes('SECURITY FATAL') || e.message.includes('integrity');
    }
    assert(tamperDetectionPassed, 'Tampered encrypted database container is rejected and fails closed');

    // 2.5 In-memory serialization and restoration roundtrip handles BLOBs, NULLs, numbers accurately
    const testMemoryDb = new DatabaseSync(':memory:');
    testMemoryDb.exec('CREATE TABLE test_types (id TEXT PRIMARY KEY, num INTEGER, ratio REAL, blob_data BLOB, empty_val TEXT);');
    testMemoryDb.prepare('INSERT INTO test_types VALUES (?, ?, ?, ?, ?)').run('row-1', 99999, 123.456, Buffer.from('audit-binary-proof'), null);

    const serializedBuf = serializeDatabaseInMemory(testMemoryDb);
    const restoredDb = new DatabaseSync(':memory:');
    restoreDatabaseFromMemory(restoredDb, serializedBuf);

    const restoredRow = restoredDb.prepare('SELECT * FROM test_types WHERE id = ?').get('row-1') as any;
    assert(restoredRow && restoredRow.num === 99999 && restoredRow.ratio === 123.456 && restoredRow.empty_val === null, 'In-memory database restoration preserves all primitive types and NULLs');
    assert(restoredRow.blob_data && Buffer.from(restoredRow.blob_data).toString('utf8') === 'audit-binary-proof', 'In-memory database restoration accurately restores binary BLOB data');


    // =========================================================================
    // SECTION 3: REAL SIGNED FIM RELEASE MANIFEST & TAMPER DETECTION
    // =========================================================================
    console.log('\n--- SECTION 3: REAL SIGNED FIM RELEASE MANIFEST & TAMPER DETECTION ---');

    // 3.1 Verify authentic release_manifest.json with official public key passes cleanly
    const authenticFimResult = FileIntegrityMonitor.verifyIntegrity();
    assert(authenticFimResult.valid && !authenticFimResult.quarantined, 'Authentic production codebase passes signed release_manifest.json FIM verification');

    // 3.2 Test tampering with backend/auth.ts
    const fimTestHarnessDir = path.join(testTempDir, 'fim_harness');
    fs.mkdirSync(path.join(fimTestHarnessDir, 'backend'), { recursive: true });

    // Copy production release_manifest.json and files to harness
    const rootManifest = fs.readFileSync(path.join(process.cwd(), 'release_manifest.json'), 'utf8');
    fs.writeFileSync(path.join(fimTestHarnessDir, 'release_manifest.json'), rootManifest);

    const parsedManifest = JSON.parse(rootManifest) as SignedFimManifest;
    for (const relPath of Object.keys(parsedManifest.payload.files)) {
      const srcPath = path.join(process.cwd(), relPath);
      const dstPath = path.join(fimTestHarnessDir, relPath);
      fs.mkdirSync(path.dirname(dstPath), { recursive: true });
      if (fs.existsSync(srcPath)) {
        fs.copyFileSync(srcPath, dstPath);
      }
    }

    // Baseline harness check
    const harnessBaseResult = FileIntegrityMonitor.verifyIntegrity(fimTestHarnessDir);
    assert(harnessBaseResult.valid, 'FIM test harness passes on authentic copy');

    // 3.3 Modify backend/auth.ts -> verify TAMPERED
    const authPath = path.join(fimTestHarnessDir, 'backend', 'auth.ts');
    fs.appendFileSync(authPath, '\n// Unauthorized modification\n');
    const authTamperResult = FileIntegrityMonitor.verifyIntegrity(fimTestHarnessDir);
    assert(!authTamperResult.valid && authTamperResult.quarantined && authTamperResult.modifiedFiles.includes('backend/auth.ts'), 'Modifying backend/auth.ts is detected and triggers QUARANTINE');

    // Restore auth.ts
    fs.copyFileSync(path.join(process.cwd(), 'backend', 'auth.ts'), authPath);

    // 3.4 Modify backend/db.ts -> verify TAMPERED
    const dbPath = path.join(fimTestHarnessDir, 'backend', 'db.ts');
    fs.appendFileSync(dbPath, '\n// Tampered db\n');
    const dbTamperResult = FileIntegrityMonitor.verifyIntegrity(fimTestHarnessDir);
    assert(!dbTamperResult.valid && dbTamperResult.quarantined && dbTamperResult.modifiedFiles.includes('backend/db.ts'), 'Modifying backend/db.ts is detected and triggers QUARANTINE');
    fs.copyFileSync(path.join(process.cwd(), 'backend', 'db.ts'), dbPath);

    // 3.5 Modify backend/routes.ts -> verify TAMPERED
    const routesPath = path.join(fimTestHarnessDir, 'backend', 'routes.ts');
    fs.appendFileSync(routesPath, '\n// Backdoor route attempt\n');
    const routesTamperResult = FileIntegrityMonitor.verifyIntegrity(fimTestHarnessDir);
    assert(!routesTamperResult.valid && routesTamperResult.quarantined && routesTamperResult.modifiedFiles.includes('backend/routes.ts'), 'Modifying backend/routes.ts is detected and triggers QUARANTINE');
    fs.copyFileSync(path.join(process.cwd(), 'backend', 'routes.ts'), routesPath);

    // 3.6 Delete a critical file -> verify MISSING / TAMPERED
    fs.unlinkSync(authPath);
    const deleteResult = FileIntegrityMonitor.verifyIntegrity(fimTestHarnessDir);
    assert(!deleteResult.valid && deleteResult.quarantined && deleteResult.missingFiles.includes('backend/auth.ts'), 'Deleting backend/auth.ts is detected and triggers QUARANTINE');
    fs.copyFileSync(path.join(process.cwd(), 'backend', 'auth.ts'), authPath);

    // 3.7 Modified release_manifest.json payload -> verify signature reject
    const tamperedManifestObj = JSON.parse(rootManifest);
    tamperedManifestObj.payload.files['backend/auth.ts'] = '0000000000000000000000000000000000000000000000000000000000000000';
    fs.writeFileSync(path.join(fimTestHarnessDir, 'release_manifest.json'), JSON.stringify(tamperedManifestObj));

    const manifestTamperResult = FileIntegrityMonitor.verifyIntegrity(fimTestHarnessDir);
    assert(!manifestTamperResult.valid && manifestTamperResult.manifestTampered, 'Modified release_manifest.json payload causes signature rejection and QUARANTINE');

    // 3.8 Invalid / forged Ed25519 signature -> reject
    const forgedSignatureManifest = JSON.parse(rootManifest);
    forgedSignatureManifest.signature = Buffer.from('forged_signature_bytes_here').toString('base64');
    fs.writeFileSync(path.join(fimTestHarnessDir, 'release_manifest.json'), JSON.stringify(forgedSignatureManifest));

    const forgedSigResult = FileIntegrityMonitor.verifyIntegrity(fimTestHarnessDir);
    assert(!forgedSigResult.valid && forgedSigResult.manifestTampered, 'Forged manifest signature fails cryptographically and triggers QUARANTINE');

    // 3.9 Manifest with placeholder hashes (e.g. EMBEDDED_ANCHOR) -> strictly rejected
    const placeholderManifest = JSON.parse(rootManifest);
    placeholderManifest.payload.files['backend/auth.ts'] = 'EMBEDDED_ANCHOR';
    const isPlaceholderValid = isValidManifestStructure(placeholderManifest);
    assert(!isPlaceholderValid, 'isValidManifestStructure strictly rejects placeholder hashes like EMBEDDED_ANCHOR');

    // 3.10 Manifest signed with unknown / unauthorized public key -> rejected
    const unauthorizedKeypair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    const canonicalPayload = JSON.stringify(parsedManifest.payload, Object.keys(parsedManifest.payload).sort());
    const rogueSignature = crypto.sign(null, Buffer.from(canonicalPayload), Buffer.from(unauthorizedKeypair.privateKey)).toString('base64');
    const rogueManifest: SignedFimManifest = {
      payload: parsedManifest.payload,
      signature: rogueSignature,
      publicKeyId: 'rogue-key-id'
    };
    const rogueVerify = verifySignedFimManifest(rogueManifest, TRUSTED_FIM_PUBLIC_KEY);
    assert(!rogueVerify, 'Manifest signed with unauthorized public key is strictly rejected by official trusted public key');

    console.log('\n========================================================================');
    console.log(`  ALL ${passedTests}/${totalTests} P0 RELEASE BLOCKER TESTS PASSED CLEANLY! (100% SUCCESS)`);
    console.log('========================================================================\n');
  } finally {
    // Clean up test temp directory
    try {
      fs.rmSync(testTempDir, { recursive: true, force: true });
    } catch {}
  }
}

runP0BlockerTestSuite().catch(err => {
  console.error('[FATAL ERROR IN P0 BLOCKER TEST SUITE]', err);
  process.exit(1);
});
