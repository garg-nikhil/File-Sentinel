import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import request from 'supertest';
import express from 'express';

import { authenticateRequest, generateIpcJwt, usedJtis } from '../backend/auth.js';
import { SecretManager } from '../backend/secretManager.js';
import { BillingService } from '../backend/billing.js';
import { corsMiddleware, getAllowedOrigins } from '../backend/securityMiddleware.js';
import {
  getDatabase,
  encryptDatabaseBuffer,
  decryptDatabaseBuffer,
  isEncryptedDatabaseFile,
  DB_MAGIC_HEADER
} from '../backend/db.js';
import { OSKeyProtection } from '../backend/osKeyProtection.js';
import { FileIntegrityMonitor } from '../backend/fimService.js';
import { signFimManifest, verifySignedFimManifest, MANUFACTURER_FIM_SIGNING_KEY } from '../backend/fimManifest.js';

describe('Security Gap Closure Test Suite (P0-1 to P0-8)', () => {
  const originalEnv = { ...process.env };

  after(() => {
    process.env = originalEnv;
  });

  // ==========================================
  // P0-1: DEV AUTHENTICATION MUST FAIL CLOSED
  // ==========================================
  describe('P0-1: Dev Authentication Fail-Closed', () => {
    let testApp: express.Application;

    before(() => {
      testApp = express();
      testApp.use(express.json());
      testApp.use(authenticateRequest);
      testApp.get('/api/protected-resource', (req: any, res: any) => {
        res.json({ status: 'ok', user: req.user });
      });
    });

    it('must reject requests when FILE_SENTINEL_DEV_MODE is undefined even if NODE_ENV=development', async () => {
      delete process.env.FILE_SENTINEL_DEV_MODE;
      process.env.NODE_ENV = 'development';

      const res = await request(testApp).get('/api/protected-resource');
      assert.strictEqual(res.status, 401, 'Must return 401 Unauthorized when FILE_SENTINEL_DEV_MODE is not true');
    });

    it('must reject requests when NODE_ENV is undefined and FILE_SENTINEL_DEV_MODE is absent', async () => {
      delete process.env.FILE_SENTINEL_DEV_MODE;
      delete process.env.NODE_ENV;

      const res = await request(testApp).get('/api/protected-resource');
      assert.strictEqual(res.status, 401);
    });

    it('must reject requests when FILE_SENTINEL_DEV_MODE="false"', async () => {
      process.env.FILE_SENTINEL_DEV_MODE = 'false';
      process.env.NODE_ENV = 'development';

      const res = await request(testApp).get('/api/protected-resource');
      assert.strictEqual(res.status, 401);
    });

    it('must accept requests only when FILE_SENTINEL_DEV_MODE === "true"', async () => {
      process.env.FILE_SENTINEL_DEV_MODE = 'true';

      const res = await request(testApp).get('/api/protected-resource');
      assert.strictEqual(res.status, 200);
      assert.ok(res.body.user);
    });
  });

  // ==========================================
  // P0-2: REMOVE SECRET FALLBACKS
  // ==========================================
  describe('P0-2: Secret Fallbacks Removed & Missing Secrets Fail Closed', () => {
    it('SecretManager.getJwtSecret must throw if JWT_SECRET is missing', () => {
      delete process.env.JWT_SECRET;
      assert.throws(() => {
        SecretManager.getJwtSecret();
      }, /JWT_SECRET environment variable is missing/);
    });

    it('SecretManager.getWebhookSecret must throw if RAZORPAY_WEBHOOK_SECRET is missing', () => {
      delete process.env.RAZORPAY_WEBHOOK_SECRET;
      assert.throws(() => {
        SecretManager.getWebhookSecret();
      }, /RAZORPAY_WEBHOOK_SECRET is missing/);
    });

    it('BillingService must fail webhook verification if webhookSecret is empty', () => {
      const billing = new BillingService(null as any, null as any, { webhookSecret: '' });
      const verified = billing.verifyWebhookSignature('{"event":"payment.captured"}', 'invalid_sig', '');
      assert.strictEqual(verified, false);
    });
  });

  // ==========================================
  // P0-3: EXACT CORS ALLOWLIST
  // ==========================================
  describe('P0-3: Exact CORS Allowlist Enforced', () => {
    let corsApp: express.Application;

    before(() => {
      process.env.ALLOWED_ORIGINS = 'https://app.filesentinel.com,https://dashboard.filesentinel.com';
      corsApp = express();
      corsApp.use(corsMiddleware);
      corsApp.get('/api/test', (_req, res) => res.json({ ok: true }));
    });

    it('must permit exact origin in allowlist', async () => {
      const res = await request(corsApp)
        .get('/api/test')
        .set('Origin', 'http://localhost:3000');
      assert.strictEqual(res.header['access-control-allow-origin'], 'http://localhost:3000');
    });

    it('must reject substring spoofing (e.g. localhost.attacker.com)', async () => {
      const res = await request(corsApp)
        .get('/api/test')
        .set('Origin', 'http://localhost:3000.attacker.com');
      assert.strictEqual(res.header['access-control-allow-origin'], undefined);
    });

    it('must reject .run.app and ai.studio substring origins if not explicitly configured', async () => {
      const res = await request(corsApp)
        .get('/api/test')
        .set('Origin', 'https://malicious-site.run.app');
      assert.strictEqual(res.header['access-control-allow-origin'], undefined);
    });

    it('OPTIONS preflight must return 403 on disallowed origin', async () => {
      const res = await request(corsApp)
        .options('/api/test')
        .set('Origin', 'https://unauthorized-domain.com');
      assert.strictEqual(res.status, 403);
    });
  });

  // ==========================================
  // P0-4: REAL DATABASE ENCRYPTION
  // ==========================================
  describe('P0-4: Authenticated Database Encryption at Rest (AES-256-GCM)', () => {
    const testPlainData = Buffer.from('SQLite format 3\0 Sample database payload content for encryption testing', 'utf8');
    const correctKey = crypto.randomBytes(32).toString('hex');
    const wrongKey = crypto.randomBytes(32).toString('hex');

    it('must encrypt plain database buffer into container with DB_MAGIC_HEADER', () => {
      const encrypted = encryptDatabaseBuffer(testPlainData, correctKey);
      assert.ok(encrypted.length > testPlainData.length);
      assert.strictEqual(encrypted.subarray(0, 12).toString('utf8'), DB_MAGIC_HEADER);
    });

    it('must decrypt accurately with correct key', () => {
      const encrypted = encryptDatabaseBuffer(testPlainData, correctKey);
      const decrypted = decryptDatabaseBuffer(encrypted, correctKey);
      assert.deepStrictEqual(decrypted, testPlainData);
    });

    it('must fail closed with wrong key', () => {
      const encrypted = encryptDatabaseBuffer(testPlainData, correctKey);
      assert.throws(() => {
        decryptDatabaseBuffer(encrypted, wrongKey);
      }, /Database decryption failed or data integrity compromised/);
    });

    it('must fail closed on tampered ciphertext', () => {
      const encrypted = encryptDatabaseBuffer(testPlainData, correctKey);
      // Tamper with ciphertext byte
      encrypted[encrypted.length - 5] ^= 0xff;
      assert.throws(() => {
        decryptDatabaseBuffer(encrypted, correctKey);
      }, /Database decryption failed or data integrity compromised/);
    });
  });

  // ==========================================
  // P0-5: REAL OS-PROTECTED DATABASE KEY
  // ==========================================
  describe('P0-5: OS-Protected Key Isolation', () => {
    it('must protect and unprotect key data correctly on the current machine', () => {
      const rawSecret = crypto.randomBytes(32);
      const protectedBlob = OSKeyProtection.protectData(rawSecret);
      assert.ok(protectedBlob.length > rawSecret.length);

      const unprotected = OSKeyProtection.unprotectData(protectedBlob);
      assert.ok(unprotected);
      assert.deepStrictEqual(unprotected, rawSecret);
    });

    it('must fail safely if protected blob is tampered', () => {
      const rawSecret = crypto.randomBytes(32);
      const protectedBlob = OSKeyProtection.protectData(rawSecret);
      // Corrupt payload
      protectedBlob[protectedBlob.length - 2] ^= 0xaa;
      const unprotected = OSKeyProtection.unprotectData(protectedBlob);
      assert.strictEqual(unprotected, null, 'Must return null and fail closed on tampered protected key');
    });
  });

  // ==========================================
  // P0-6: TAURI SECURITY BOUNDARY
  // ==========================================
  describe('P0-6: Tauri Least-Privilege Allowlist Boundary', () => {
    it('tauri.conf.json must enforce least-privilege for fs and shell', () => {
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
    });
  });

  // ==========================================
  // P0-7: FILE INTEGRITY MONITORING (FIM)
  // ==========================================
  describe('P0-7: Signed Manufacturer Manifest File Integrity Monitoring', () => {
    const tmpDir = path.join(process.cwd(), '.tmp_test_fim_' + Date.now());

    before(() => {
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(path.join(tmpDir, 'test_module.ts'), 'export const a = 1;');
    });

    after(() => {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
      FileIntegrityMonitor.resetToEmbeddedManifest();
    });

    it('must pass integrity when files match manufacturer-signed manifest', () => {
      const fileHash = FileIntegrityMonitor.computeFileHash(path.join(tmpDir, 'test_module.ts'))!;
      const manifest = signFimManifest({
        version: '8.2.0-test',
        issuedAt: new Date().toISOString(),
        files: {
          'test_module.ts': fileHash
        }
      });

      FileIntegrityMonitor.setManifest(manifest);
      const res = FileIntegrityMonitor.verifyIntegrity(tmpDir);
      assert.strictEqual(res.valid, true);
      assert.strictEqual(res.quarantined, false);
      assert.strictEqual(res.modifiedFiles.length, 0);
    });

    it('must detect tampering when a file is modified on disk', () => {
      // Modify file on disk
      fs.writeFileSync(path.join(tmpDir, 'test_module.ts'), 'export const a = 2; // modified attacker code');

      const res = FileIntegrityMonitor.verifyIntegrity(tmpDir);
      assert.strictEqual(res.valid, false);
      assert.strictEqual(res.quarantined, true);
      assert.ok(res.modifiedFiles.includes('test_module.ts'));
    });

    it('must fail closed when manifest signature itself is tampered', () => {
      const fileHash = FileIntegrityMonitor.computeFileHash(path.join(tmpDir, 'test_module.ts'))!;
      const manifest = signFimManifest({
        version: '8.2.0-test',
        issuedAt: new Date().toISOString(),
        files: {
          'test_module.ts': fileHash
        }
      });

      // Tamper signature
      manifest.signature = crypto.randomBytes(32).toString('hex');
      FileIntegrityMonitor.setManifest(manifest);

      const res = FileIntegrityMonitor.verifyIntegrity(tmpDir);
      assert.strictEqual(res.valid, false);
      assert.strictEqual(res.quarantined, true);
      assert.strictEqual(res.manifestTampered, true);
    });
  });

  // ==========================================
  // P0-8: REMOVE STATIC IPC ADMIN BYPASS
  // ==========================================
  describe('P0-8: Static IPC Admin Bypass Removed & Short-Lived Tokens Enforced', () => {
    let authApp: express.Application;
    const testIpcSecret = 'test-ipc-hmac-secret-2026-very-secure';

    before(() => {
      process.env.FILE_SENTINEL_IPC_SECRET = testIpcSecret;
      process.env.FILE_SENTINEL_DEV_MODE = 'false';

      authApp = express();
      authApp.use(express.json());
      authApp.use(authenticateRequest);
      authApp.get('/api/ipc-action', (req: any, res: any) => {
        res.json({ status: 'ok', user: req.user });
      });
    });

    it('must reject static X-FS-IPC-Secret header (no static admin bypass)', async () => {
      const res = await request(authApp)
        .get('/api/ipc-action')
        .set('x-fs-ipc-secret', testIpcSecret);
      assert.strictEqual(res.status, 401, 'Static IPC secret must NOT grant admin access');
    });

    it('must accept valid signed short-lived IPC JWT token from loopback', async () => {
      const token = generateIpcJwt({
        deviceId: 'dev-loopback-01',
        orgId: 'org-test-01',
        role: 'OPERATOR'
      }, testIpcSecret);

      const res = await request(authApp)
        .get('/api/ipc-action')
        .set('x-fs-ipc-token', token)
        .set('x-device-id', 'dev-loopback-01');

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.user.role, 'OPERATOR');
      assert.strictEqual(res.body.user.deviceId, 'dev-loopback-01');
    });

    it('must reject replayed IPC tokens (anti-replay jti check)', async () => {
      const fixedJti = 'fixed-replay-jti-' + Date.now();
      const token = generateIpcJwt({
        deviceId: 'dev-loopback-01',
        orgId: 'org-test-01',
        role: 'OPERATOR',
        jti: fixedJti
      }, testIpcSecret);

      // First use: ok
      const res1 = await request(authApp)
        .get('/api/ipc-action')
        .set('x-fs-ipc-token', token);
      assert.strictEqual(res1.status, 200);

      // Second use (replayed): rejected 401
      const res2 = await request(authApp)
        .get('/api/ipc-action')
        .set('x-fs-ipc-token', token);
      assert.strictEqual(res2.status, 401, 'Replayed token must be rejected');
    });

    it('must reject expired IPC tokens', async () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredToken = generateIpcJwt({
        deviceId: 'dev-loopback-01',
        orgId: 'org-test-01',
        role: 'OPERATOR',
        iat: now - 3600,
        exp: now - 1800 // expired 30 minutes ago
      }, testIpcSecret);

      const res = await request(authApp)
        .get('/api/ipc-action')
        .set('x-fs-ipc-token', expiredToken);
      assert.strictEqual(res.status, 401, 'Expired token must be rejected');
    });

    it('must reject IPC tokens with mismatched device ID header', async () => {
      const token = generateIpcJwt({
        deviceId: 'dev-bound-machine-A',
        orgId: 'org-test-01',
        role: 'OPERATOR'
      }, testIpcSecret);

      const res = await request(authApp)
        .get('/api/ipc-action')
        .set('x-fs-ipc-token', token)
        .set('x-device-id', 'dev-impostor-machine-B');

      assert.strictEqual(res.status, 401, 'Device binding mismatch must be rejected');
    });
  });
});
