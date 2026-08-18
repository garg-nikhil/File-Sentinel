import express from 'express';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { createApiRouter } from '../backend/routes.js';
import { securityHeaders, corsMiddleware, enforceContentType, rateLimiter, safeErrorHandler } from '../backend/securityMiddleware.js';

async function runNoLocalDeletionRegressionTest() {
  console.log('================================================================');
  console.log('  FileSentinel Non-Destructive Cloud Upload & Deletion Ban Test  ');
  console.log('================================================================');

  let passed = 0;
  let failed = 0;

  // Spin up test Express app
  const app = express();
  app.use(securityHeaders);
  app.use(corsMiddleware);
  app.use(express.json({ limit: '100kb' }));
  app.use(enforceContentType);
  app.use('/api', createApiRouter());
  app.use('/api', safeErrorHandler);

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address() as any;
  const baseUrl = `http://localhost:${address.port}/api`;

  const tempDir = path.join(process.cwd(), 'test_temp_regression');
  if (fs.existsSync(tempDir)) fs.rmSync(tempDir, { recursive: true, force: true });
  fs.mkdirSync(tempDir, { recursive: true });

  const tempFilePath = path.join(tempDir, 'FILE-0123.txt');
  const fileContent = 'TEST DATA: Sensitive Personal Information 123-45-6789';
  fs.writeFileSync(tempFilePath, fileContent);
  const originalSha256 = crypto.createHash('sha256').update(fileContent).digest('hex');
  const fileSize = fs.statSync(tempFilePath).size;

  try {
    const { getDatabase } = await import('../backend/db.js');
    const db = getDatabase();

    db.prepare('INSERT OR IGNORE INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)').run('org-default-dev', 'Default Dev Organization', new Date().toISOString());
    db.prepare(`
      INSERT OR REPLACE INTO licenses (license_id, organization_id, plan_id, status, issued_at, starts_at, expires_at, max_users, max_devices, scan_limit, feature_flags, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run('lic-test-regression', 'org-default-dev', 'plan-enterprise', 'ACTIVE', new Date().toISOString(), new Date().toISOString(), new Date(Date.now() + 86400000 * 365).toISOString(), 10, 10, -1, JSON.stringify(['LOCAL_SCANNING', 'CLOUD_UPLOADS', 'CLOUD_EVIDENCE_UPLOAD', 'AUDIT_ENGINE']), new Date().toISOString(), new Date().toISOString());

    db.prepare(`
      INSERT OR IGNORE INTO scans (scan_id, root_path, start_time, status, org_id, user_id)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run('scan_test', tempDir, new Date().toISOString(), 'COMPLETED', 'org-default-dev', 'user-default-dev');

    const fileId = 'FILE-0123';
    db.prepare(`
      INSERT OR REPLACE INTO files (file_id, scan_id, path, filename, extension, size, sha256, classification, risk_score, scan_status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(fileId, 'scan_test', tempFilePath, 'FILE-0123.txt', '.txt', fileSize, originalSha256, 'RESTRICTED', 85, 'SUCCESS');

    // 3: Call the actual Phase 6A upload endpoint
    const uploadRes = await fetch(`${baseUrl}/cloud-uploads/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ file_ids: [fileId] })
    });

    const uploadJson = await uploadRes.json() as any;

    if (uploadRes.status !== 200 || !uploadJson.success) {
      throw new Error(`Upload endpoint failed: status ${uploadRes.status}, body: ${JSON.stringify(uploadJson)}`);
    }

    console.log('  ✔ [TEST 3] Actual Phase 6A upload endpoint invoked successfully.');
    passed++;

    const resultItem = uploadJson.results?.[0];
    if (!resultItem || !resultItem.success) {
      throw new Error('Upload result item missing or unsuccessful');
    }
    const cloudObjectName = resultItem.cloud_object_name;
    const storageProvider = (await import('../backend/quarantineService.js')).getCloudStorageProvider();
    const remoteMeta = await storageProvider.getMetadata(cloudObjectName);

    if (!remoteMeta || !remoteMeta.exists || remoteMeta.sha256 !== originalSha256) {
      throw new Error(`Cloud verification failed or hash mismatch: ${JSON.stringify(remoteMeta)}`);
    }
    console.log('  ✔ [TEST 4, 5] Cloud upload completed and remote object verified successfully.');
    passed++;

    const localExistsAfterUpload = fs.existsSync(tempFilePath);
    if (!localExistsAfterUpload) {
      throw new Error('CRITICAL FAILURE: Local file was deleted during cloud upload!');
    }
    console.log('  ✔ [TEST 6] Local file verified still exists on disk (Zero deletion).');
    passed++;

    const currentLocalContent = fs.readFileSync(tempFilePath);
    const currentLocalSha256 = crypto.createHash('sha256').update(currentLocalContent).digest('hex');
    if (currentLocalSha256 !== originalSha256) {
      throw new Error('Local file SHA-256 changed!');
    }
    console.log('  ✔ [TEST 7] Local file SHA-256 remains unchanged.');
    passed++;

    const responseString = JSON.stringify(resultItem);
    if (responseString.includes('local_deleted') && resultItem.local_deleted === true) {
      throw new Error('Response improperly indicates local_deleted=true.');
    }
    console.log('  ✔ [TEST 8] Response verified to contain zero local_deleted=true flags.');
    passed++;

    const uploadDbRecord = db.prepare('SELECT * FROM file_cloud_uploads WHERE file_id = ?').get(fileId) as any;
    if (!uploadDbRecord || uploadDbRecord.upload_status !== 'UPLOADED') {
      throw new Error('Database upload record incorrect.');
    }
    console.log('  ✔ [TEST 9] Database upload state verified non-destructive (UPLOADED without deletion state).');
    passed++;

    const removeRes = await fetch(`${baseUrl}/quarantine/${fileId}/upload-and-remove`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });

    if (removeRes.status === 404) {
      console.log('  ✔ [TEST 10] Destructive endpoint POST /api/quarantine/:file_id/upload-and-remove correctly returns 404 Not Found.');
      passed++;
    } else {
      throw new Error(`Expected 404 for upload-and-remove, got ${removeRes.status}`);
    }

    if (!fs.existsSync(tempFilePath)) {
      throw new Error('CRITICAL FAILURE: Calling upload-and-remove deleted the local file despite returning 404!');
    }
    console.log('  ✔ [TEST 11] Local file verified still intact after hitting disabled route.');
    passed++;

  } catch (err: any) {
    console.error('  ✘ No-Local-Deletion Regression Test failed:', err);
    failed++;
  } finally {
    if (fs.existsSync(tempDir)) {
      try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}
    }
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  console.log('================================================================');
  console.log(`  RESULTS: ${passed} Passed, ${failed} Failed`);
  console.log('================================================================');

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runNoLocalDeletionRegressionTest().catch(e => {
  console.error('Fatal test error:', e);
  process.exit(1);
});
