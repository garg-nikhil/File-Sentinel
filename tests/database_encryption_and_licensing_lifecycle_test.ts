import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

import {
  getDatabase,
  encryptDatabaseBuffer,
  decryptDatabaseBuffer,
  persistDatabaseToEncryptedFile,
  isEncryptedDatabaseFile,
  DB_MAGIC_HEADER
} from '../backend/db.js';
import { OSKeyProtection } from '../backend/osKeyProtection.js';
import {
  OfflineLicenseEngine,
  getOrCreateDevKeyPair,
  TRUSTED_PUBLIC_KEYS,
  SignedLicenseLease,
  LicenseLeasePayload
} from '../backend/licensing/offlineLicense.js';
import { ProtectedLicenseStore } from '../backend/licensing/protectedLicenseStore.js';

async function runLifecycleTests() {
  console.log('\n========================================================================');
  console.log('  FILE-SENTINEL: Database Encryption & Offline Licensing Lifecycle Test  ');
  console.log('========================================================================\n');

  const originalEnv = { ...process.env };
  const tempTestDir = path.join(process.cwd(), '.tmp_test_lifecycle_' + Date.now());

  try {
    fs.mkdirSync(tempTestDir, { recursive: true });

    // =========================================================================
    // 1. REAL DATABASE ENCRYPTION LIFECYCLE & PERSISTENCE
    // =========================================================================
    console.log('[LIFECYCLE-1] Testing Database Creation, Encrypted Persistence, Restart, and Reading...');
    {
      const encDbPath = path.join(tempTestDir, 'production_lifecycle.db');

      // 1. Create DB and insert records
      const db1 = getDatabase(encDbPath);
      db1.exec(`
        CREATE TABLE IF NOT EXISTS audit_records (
          id TEXT PRIMARY KEY,
          title TEXT NOT NULL,
          classification TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
      `);

      const insertStmt = db1.prepare('INSERT INTO audit_records (id, title, classification, created_at) VALUES (?, ?, ?, ?)');
      insertStmt.run('rec-001', 'Confidential Financial Statement', 'RESTRICTED', new Date().toISOString());
      insertStmt.run('rec-002', 'Employee PII Database', 'CONFIDENTIAL', new Date().toISOString());

      // Persist to encrypted container on disk
      persistDatabaseToEncryptedFile(db1, encDbPath);

      // Verify the on-disk file is strictly encrypted (starts with DB_MAGIC_HEADER and NOT SQLite plaintext)
      assert.ok(fs.existsSync(encDbPath), 'Encrypted database file must exist on disk');
      const diskBytes = fs.readFileSync(encDbPath);
      assert.strictEqual(diskBytes.subarray(0, 12).toString('utf8'), DB_MAGIC_HEADER, 'On-disk DB must have encrypted magic header');
      assert.notStrictEqual(diskBytes.subarray(0, 15).toString('utf8'), 'SQLite format 3', 'Live production database must NEVER exist as plaintext on disk');

      // Ensure no temporary decrypted files exist in directory
      const lingeringTmpFiles = fs.readdirSync(tempTestDir).filter(f => f.startsWith('.tmp_') && f.endsWith('.db'));
      assert.strictEqual(lingeringTmpFiles.length, 0, 'No temporary plaintext DB files must linger on disk');

      // 2. Restart simulation: Open fresh instance from encrypted container
      const db2 = getDatabase(encDbPath);
      const rows = db2.prepare('SELECT id, title, classification FROM audit_records ORDER BY id ASC').all() as any[];
      assert.strictEqual(rows.length, 2, 'Restarted database must load all persisted records');
      assert.strictEqual(rows[0].id, 'rec-001');
      assert.strictEqual(rows[0].title, 'Confidential Financial Statement');
      assert.strictEqual(rows[1].id, 'rec-002');
      console.log('  ✓ Database lifecycle: create → write → persist → restart → read verified successfully');
    }

    // =========================================================================
    // 2. DATABASE TAMPER & WRONG KEY DETECTION (FAIL-CLOSED)
    // =========================================================================
    console.log('\n[LIFECYCLE-2] Testing Database Tampering and Wrong Key Detection (Fail-Closed)...');
    {
      const encDbPath = path.join(tempTestDir, 'tamper_test.db');
      const testDb = getDatabase(encDbPath);
      testDb.exec('CREATE TABLE IF NOT EXISTS secrets (k TEXT PRIMARY KEY, v TEXT);');
      testDb.prepare('INSERT INTO secrets VALUES (?, ?)').run('api_key', 'super-secret-production-token');
      persistDatabaseToEncryptedFile(testDb, encDbPath);

      // 1. Tamper with file contents on disk
      const diskBytes = fs.readFileSync(encDbPath);
      diskBytes[diskBytes.length - 10] ^= 0x55; // Corrupt ciphertext
      const tamperedDbPath = path.join(tempTestDir, 'tampered_corrupt.db');
      fs.writeFileSync(tamperedDbPath, diskBytes);

      assert.throws(() => {
        getDatabase(tamperedDbPath);
      }, /SECURITY FATAL|Database decryption failed/, 'Tampered encrypted database must fail closed with fatal error');

      // 2. Test decryption with incorrect key
      const wrongKey = crypto.randomBytes(32).toString('hex');
      const originalEncBytes = fs.readFileSync(encDbPath);
      assert.throws(() => {
        decryptDatabaseBuffer(originalEncBytes, wrongKey);
      }, /Database decryption failed/, 'Decryption with wrong key must fail closed');

      console.log('  ✓ Database tampering and incorrect key fail closed immediately without data exposure');
    }

    // =========================================================================
    // 3. OFFLINE LICENSING MINTING GATING & ADVERSARIAL VALIDATION
    // =========================================================================
    console.log('\n[LIFECYCLE-3] Testing Production Offline Licensing Minting Gating & Verification...');
    {
      // 1. In production or without FILE_SENTINEL_DEV_MODE=true, dev key generation must throw
      process.env.NODE_ENV = 'production';
      delete process.env.FILE_SENTINEL_DEV_MODE;

      assert.throws(() => {
        getOrCreateDevKeyPair();
      }, /SECURITY FATAL/, 'Production code must NEVER generate/create/sign a license locally');

      const dummyPayload: LicenseLeasePayload = {
        licenseId: 'lic-forged-001',
        organizationId: 'org-tenant-a',
        deviceLimit: 10,
        modules: ['LOCAL_SCANNING', 'AUDIT_ENGINE'],
        issuedAt: new Date().toISOString(),
        notBefore: new Date(Date.now() - 3600000).toISOString(),
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
        licenseVersion: '8.2.0'
      };

      assert.throws(() => {
        OfflineLicenseEngine.signLease(dummyPayload, 'dummy-key');
      }, /SECURITY FATAL/, 'Production code must reject local license signing');

      // 2. Verification of official vs forged licenses
      const testMemDb = getDatabase(':memory:');
      const nowIso = new Date().toISOString();
      testMemDb.prepare(`
        INSERT OR IGNORE INTO organizations (org_id, name, suspended, created_at)
        VALUES (?, ?, 0, ?)
      `).run('org-tenant-a', 'Tenant A', nowIso);

      const engine = new OfflineLicenseEngine(testMemDb);

      // Forged lease (signed with untrusted key)
      const fakeKeyPair = crypto.generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      const forgedCanonical = JSON.stringify(dummyPayload, Object.keys(dummyPayload).sort());
      const forgedSig = crypto.sign(null, Buffer.from(forgedCanonical, 'utf8'), fakeKeyPair.privateKey).toString('base64');
      const forgedLease: SignedLicenseLease = {
        payload: dummyPayload,
        signature: forgedSig,
        publicKeyId: 'fs-root-2026' // Attacker claiming root key ID
      };

      const forgedResult = engine.validateLease(forgedLease, { orgId: 'org-tenant-a' });
      assert.strictEqual(forgedResult.valid, false, 'Forged signature must be rejected');

      // Wrong tenant verification
      process.env.FILE_SENTINEL_DEV_MODE = 'true';
      process.env.NODE_ENV = 'development';
      const devKeys = getOrCreateDevKeyPair();
      const validDevLease = OfflineLicenseEngine.signLease(dummyPayload, devKeys.privateKey, 'fs-dev-key');

      const wrongTenantResult = engine.validateLease(validDevLease, { orgId: 'org-impostor-tenant' });
      assert.strictEqual(wrongTenantResult.valid, false, 'License for different tenant must be rejected');
      assert.strictEqual(wrongTenantResult.status, 'ORG_MISMATCH');

      // Expired license verification
      const expiredPayload: LicenseLeasePayload = {
        ...dummyPayload,
        issuedAt: new Date(Date.now() - 30 * 86400000).toISOString(),
        notBefore: new Date(Date.now() - 30 * 86400000).toISOString(),
        expiresAt: new Date(Date.now() - 10 * 86400000).toISOString()
      };
      const expiredLease = OfflineLicenseEngine.signLease(expiredPayload, devKeys.privateKey, 'fs-dev-key');
      const expiredResult = engine.validateLease(expiredLease, { orgId: 'org-tenant-a' });
      assert.strictEqual(expiredResult.valid, false, 'Expired license must be rejected');
      assert.strictEqual(expiredResult.status, 'EXPIRED');

      console.log('  ✓ Production license minting prevented; forged, expired, and cross-tenant leases rejected');
    }

    // =========================================================================
    // 4. STABLE OS DEVICE IDENTITY
    // =========================================================================
    console.log('\n[LIFECYCLE-4] Testing Stable OS Device Identity & Protected Installation Secret...');
    {
      const osId = ProtectedLicenseStore.getStableOsIdentity();
      assert.ok(osId && osId.length > 5, 'Stable OS identity must be non-empty string');

      const installSecret1 = ProtectedLicenseStore.getInstallationSecret();
      const installSecret2 = ProtectedLicenseStore.getInstallationSecret();
      assert.strictEqual(installSecret1, installSecret2, 'Installation secret must be persistent');

      const fp1 = ProtectedLicenseStore.getMachineFingerprint();
      const fp2 = ProtectedLicenseStore.getMachineFingerprint();
      assert.strictEqual(fp1, fp2, 'Device fingerprint must be deterministic across calls on the same OS installation');
      console.log('  ✓ Stable OS device identity and protected installation secret verified');
    }

    console.log('\n========================================================================');
    console.log('  ALL DATABASE ENCRYPTION & LICENSING LIFECYCLE TESTS PASSED!           ');
    console.log('========================================================================\n');
    process.exit(0);
  } finally {
    process.env = originalEnv;
    try { fs.rmSync(tempTestDir, { recursive: true, force: true }); } catch {}
  }
}

runLifecycleTests().catch((err) => {
  console.error('\n❌ Lifecycle Tests Failed:', err);
  process.exit(1);
});
