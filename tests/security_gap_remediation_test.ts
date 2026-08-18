import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import request from 'supertest';
import express from 'express';

import { authenticateRequest, generateIpcJwt } from '../backend/auth.js';
import { SecretManager } from '../backend/secretManager.js';
import { BillingService } from '../backend/billing.js';
import { corsMiddleware } from '../backend/securityMiddleware.js';
import {
  getDatabase,
  encryptDatabaseBuffer,
  decryptDatabaseBuffer,
  isEncryptedDatabaseFile,
  DB_MAGIC_HEADER
} from '../backend/db.js';
import { OSKeyProtection } from '../backend/osKeyProtection.js';
import { FileIntegrityMonitor } from '../backend/fimService.js';
import { verifySignedFimManifest, TRUSTED_FIM_PUBLIC_KEY, SignedFimManifest } from '../backend/fimManifest.js';
import { OfflineLicenseEngine, TRUSTED_PUBLIC_KEYS } from '../backend/licensing/offlineLicense.js';
import { ProtectedLicenseStore } from '../backend/licensing/protectedLicenseStore.js';

async function runSecurityGapTests() {
  console.log('\n========================================================================');
  console.log('  FILE-SENTINEL: Security Gap Remediation Test Suite (P0-1 to P0-8)     ');
  console.log('========================================================================\n');

  const originalEnv = { ...process.env };

  try {
    // -------------------------------------------------------------------------
    // P0-1: DEV AUTHENTICATION MUST FAIL CLOSED
    // -------------------------------------------------------------------------
    console.log('[P0-1] Testing Dev Authentication Fail-Closed...');
    {
      const testApp = express();
      testApp.use(express.json());
      testApp.use(authenticateRequest);
      testApp.get('/api/protected-resource', (req: any, res: any) => {
        res.json({ status: 'ok', user: req.user });
      });

      delete process.env.FILE_SENTINEL_DEV_MODE;
      process.env.NODE_ENV = 'development';
      let res = await request(testApp).get('/api/protected-resource');
      assert.strictEqual(res.status, 401, 'Must return 401 when FILE_SENTINEL_DEV_MODE is not true');

      delete process.env.FILE_SENTINEL_DEV_MODE;
      delete process.env.NODE_ENV;
      res = await request(testApp).get('/api/protected-resource');
      assert.strictEqual(res.status, 401, 'Must return 401 when NODE_ENV is undefined');

      process.env.FILE_SENTINEL_DEV_MODE = 'false';
      process.env.NODE_ENV = 'development';
      res = await request(testApp).get('/api/protected-resource');
      assert.strictEqual(res.status, 401, 'Must return 401 when FILE_SENTINEL_DEV_MODE is false');

      process.env.FILE_SENTINEL_DEV_MODE = 'true';
      res = await request(testApp).get('/api/protected-resource');
      assert.strictEqual(res.status, 200, 'Must accept dev auth when FILE_SENTINEL_DEV_MODE is true');
      console.log('  ✓ Dev Authentication strictly fails closed unless FILE_SENTINEL_DEV_MODE === "true"');
    }

    // -------------------------------------------------------------------------
    // P0-2: REMOVE SECRET FALLBACKS
    // -------------------------------------------------------------------------
    console.log('\n[P0-2] Testing Secret Fallbacks Removed & Missing Secrets Fail Closed...');
    {
      delete process.env.JWT_SECRET;
      assert.throws(() => {
        SecretManager.getJwtSecret();
      }, /JWT_SECRET environment variable is missing/);

      delete process.env.RAZORPAY_WEBHOOK_SECRET;
      assert.throws(() => {
        SecretManager.getWebhookSecret();
      }, /RAZORPAY_WEBHOOK_SECRET is missing/);

      const billing = new BillingService(null as any, null as any, { webhookSecret: '' });
      const verified = billing.verifyWebhookSignature('{"event":"payment.captured"}', 'invalid_sig', '');
      assert.strictEqual(verified, false);
      console.log('  ✓ Hardcoded secret fallbacks removed; missing secrets fail closed');
    }

    // -------------------------------------------------------------------------
    // P0-3: EXACT CORS ALLOWLIST
    // -------------------------------------------------------------------------
    console.log('\n[P0-3] Testing Exact CORS Allowlist Enforced...');
    {
      process.env.ALLOWED_ORIGINS = 'https://app.filesentinel.com,https://dashboard.filesentinel.com';
      const corsApp = express();
      corsApp.use(corsMiddleware);
      corsApp.get('/api/test', (_req, res) => res.json({ ok: true }));

      let res = await request(corsApp).get('/api/test').set('Origin', 'http://localhost:3000');
      assert.strictEqual(res.header['access-control-allow-origin'], 'http://localhost:3000');

      res = await request(corsApp).get('/api/test').set('Origin', 'http://localhost:3000.attacker.com');
      assert.strictEqual(res.header['access-control-allow-origin'], undefined);

      res = await request(corsApp).get('/api/test').set('Origin', 'https://malicious-site.run.app');
      assert.strictEqual(res.header['access-control-allow-origin'], undefined);

      res = await request(corsApp).options('/api/test').set('Origin', 'https://unauthorized-domain.com');
      assert.strictEqual(res.status, 403);
      console.log('  ✓ CORS allowlist strictly enforced without wildcard spoofing');
    }

    // -------------------------------------------------------------------------
    // P0-4: REAL DATABASE ENCRYPTION
    // -------------------------------------------------------------------------
    console.log('\n[P0-4] Testing Authenticated Database Encryption at Rest (AES-256-GCM)...');
    {
      const testPlainData = Buffer.from('SQLite format 3\0 Sample database payload content for encryption testing', 'utf8');
      const correctKey = crypto.randomBytes(32).toString('hex');
      const wrongKey = crypto.randomBytes(32).toString('hex');

      const encrypted = encryptDatabaseBuffer(testPlainData, correctKey);
      assert.ok(encrypted.length > testPlainData.length);
      assert.strictEqual(encrypted.subarray(0, 12).toString('utf8'), DB_MAGIC_HEADER);

      const decrypted = decryptDatabaseBuffer(encrypted, correctKey);
      assert.deepStrictEqual(decrypted, testPlainData);

      assert.throws(() => {
        decryptDatabaseBuffer(encrypted, wrongKey);
      }, /Database decryption failed or data integrity compromised/);

      // Tampered byte test
      const tampered = Buffer.from(encrypted);
      tampered[tampered.length - 5] ^= 0xff;
      assert.throws(() => {
        decryptDatabaseBuffer(tampered, correctKey);
      }, /Database decryption failed or data integrity compromised/);

      console.log('  ✓ Authenticated AES-256-GCM database encryption and fail-closed integrity verified');
    }

    // -------------------------------------------------------------------------
    // P0-5: REAL OS-PROTECTED DATABASE KEY
    // -------------------------------------------------------------------------
    console.log('\n[P0-5] Testing OS-Protected Key Isolation...');
    {
      const rawSecret = crypto.randomBytes(32);
      const protectedBlob = OSKeyProtection.protectData(rawSecret);
      assert.ok(protectedBlob.length > rawSecret.length);

      const unprotected = OSKeyProtection.unprotectData(protectedBlob);
      assert.ok(unprotected);
      assert.deepStrictEqual(unprotected, rawSecret);

      const tamperedBlob = Buffer.from(protectedBlob);
      tamperedBlob[tamperedBlob.length - 2] ^= 0xaa;
      const tamperedUnprotect = OSKeyProtection.unprotectData(tamperedBlob);
      assert.strictEqual(tamperedUnprotect, null, 'Must return null and fail closed on tampered key');
      console.log('  ✓ OS key protection primitives protect database master key and fail closed on tamper');
    }

    // -------------------------------------------------------------------------
    // P0-6: TAURI SECURITY BOUNDARY
    // -------------------------------------------------------------------------
    console.log('\n[P0-6] Testing Tauri Least-Privilege Allowlist Boundary...');
    {
      const tauriConfigPath = path.join(process.cwd(), 'src-tauri', 'tauri.conf.json');
      assert.ok(fs.existsSync(tauriConfigPath), 'tauri.conf.json must exist');

      const config = JSON.parse(fs.readFileSync(tauriConfigPath, 'utf8'));
      const allowlist = config.tauri.allowlist;

      assert.strictEqual(allowlist.all, false);
      assert.strictEqual(allowlist.fs.all, false);
      assert.strictEqual(allowlist.shell.all, false);
      assert.strictEqual(allowlist.shell.execute, false);
      assert.strictEqual(allowlist.shell.sidecar, false);
      assert.ok(config.tauri.security.csp.length > 0);
      console.log('  ✓ Tauri configuration locked down to least-privilege');
    }

    // -------------------------------------------------------------------------
    // P0-7: FILE INTEGRITY MONITORING (FIM)
    // -------------------------------------------------------------------------
    console.log('\n[P0-7] Testing Signed Manufacturer Manifest File Integrity Monitoring...');
    {
      const tmpDir = path.join(process.cwd(), '.tmp_test_fim_' + Date.now());
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(path.join(tmpDir, 'test_module.ts'), 'export const a = 1;');

      const testKeyPair = crypto.generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });

      const fileHash = FileIntegrityMonitor.computeFileHash(path.join(tmpDir, 'test_module.ts'))!;
      const canonicalizeJson = (obj: any): string => {
        if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
        if (Array.isArray(obj)) return '[' + obj.map(canonicalizeJson).join(',') + ']';
        const keys = Object.keys(obj).sort();
        return '{' + keys.map(k => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`).join(',') + '}';
      };

      const payload = {
        version: '8.2.0-test',
        issuedAt: new Date().toISOString(),
        files: {
          'test_module.ts': fileHash
        }
      };
      const canonical = canonicalizeJson(payload);
      const signature = crypto.sign(null, Buffer.from(canonical, 'utf8'), testKeyPair.privateKey).toString('base64');
      const manifest: SignedFimManifest = {
        payload,
        signature
      };

      fs.writeFileSync(path.join(tmpDir, 'release_manifest.json'), JSON.stringify(manifest));
      let res = verifySignedFimManifest(manifest, testKeyPair.publicKey);
      assert.strictEqual(res, true);

      // Modify file on disk and verify FIM integrity
      fs.writeFileSync(path.join(tmpDir, 'test_module.ts'), 'export const a = 2; // tampered');
      const verifyRes = FileIntegrityMonitor.verifyIntegrity(tmpDir);
      assert.strictEqual(verifyRes.valid, false);

      // Tamper signature
      const tamperedManifest: SignedFimManifest = { ...manifest, signature: Buffer.from('invalid-sig').toString('base64') };
      assert.strictEqual(verifySignedFimManifest(tamperedManifest, testKeyPair.publicKey), false);

      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
      console.log('  ✓ Ed25519 asymmetric manufacturer signature verification and tampering detection verified');
    }

    // -------------------------------------------------------------------------
    // P0-8: REMOVE STATIC IPC ADMIN BYPASS
    // -------------------------------------------------------------------------
    console.log('\n[P0-8] Testing Static IPC Admin Bypass Removed & Short-Lived Tokens Enforced...');
    {
      const testIpcSecret = 'test-ipc-hmac-secret-2026-very-secure';
      process.env.FILE_SENTINEL_IPC_SECRET = testIpcSecret;
      process.env.FILE_SENTINEL_DEV_MODE = 'false';

      const authApp = express();
      authApp.use(express.json());
      authApp.use(authenticateRequest);
      authApp.get('/api/ipc-action', (req: any, res: any) => {
        res.json({ status: 'ok', user: req.user });
      });

      // Reject static header
      let res = await request(authApp).get('/api/ipc-action').set('x-fs-ipc-secret', testIpcSecret);
      assert.strictEqual(res.status, 401);

      // Accept short-lived JWT
      const token = generateIpcJwt({
        deviceId: 'dev-loopback-01',
        orgId: 'org-test-01',
        role: 'OPERATOR'
      }, testIpcSecret);

      res = await request(authApp)
        .get('/api/ipc-action')
        .set('x-fs-ipc-token', token)
        .set('x-device-id', 'dev-loopback-01');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.user.role, 'OPERATOR');

      // Replay rejected
      const replayJti = 'fixed-jti-' + Date.now();
      const replayToken = generateIpcJwt({
        deviceId: 'dev-loopback-01',
        orgId: 'org-test-01',
        role: 'OPERATOR',
        jti: replayJti
      }, testIpcSecret);

      res = await request(authApp).get('/api/ipc-action').set('x-fs-ipc-token', replayToken);
      assert.strictEqual(res.status, 200);
      res = await request(authApp).get('/api/ipc-action').set('x-fs-ipc-token', replayToken);
      assert.strictEqual(res.status, 401, 'Replayed token must be rejected');

      // Expired rejected
      const now = Math.floor(Date.now() / 1000);
      const expiredToken = generateIpcJwt({
        deviceId: 'dev-loopback-01',
        orgId: 'org-test-01',
        role: 'OPERATOR',
        iat: now - 3600,
        exp: now - 1800
      }, testIpcSecret);
      res = await request(authApp).get('/api/ipc-action').set('x-fs-ipc-token', expiredToken);
      assert.strictEqual(res.status, 401, 'Expired token must be rejected');
      console.log('  ✓ Static IPC admin bypass removed; short-lived anti-replay JWT tokens enforced');
    }

    console.log('\n========================================================================');
    console.log('  ALL P0-1 to P0-8 SECURITY GAP REMEDIATION TESTS PASSED CLEANLY!       ');
    console.log('========================================================================\n');
    process.exit(0);
  } finally {
    process.env = originalEnv;
  }
}

runSecurityGapTests().catch((err) => {
  console.error('\n❌ Security Gap Remediation Tests Failed:', err);
  process.exit(1);
});
