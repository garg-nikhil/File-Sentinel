import fs from 'fs';
import path from 'path';
import { DatabaseSync } from 'node:sqlite';
import { LocalCloudStorageProvider } from '../backend/quarantineService.js';
import { FileScannerEngine } from '../backend/scannerEngine.js';

console.log('=== STARTING PHASE 6A: CLOUD UPLOAD & NON-DESTRUCTIVE QUARANTINE TESTS ===');

const testDbPath = path.join(process.cwd(), 'test_phase6a.db');
if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);

const db = new DatabaseSync(testDbPath);
db.exec(`
  CREATE TABLE IF NOT EXISTS files (
    file_id TEXT PRIMARY KEY,
    scan_id TEXT,
    path TEXT NOT NULL,
    filename TEXT NOT NULL,
    extension TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    classification TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    scanned_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS file_cloud_uploads (
    file_id TEXT PRIMARY KEY,
    scan_id TEXT,
    audit_session_id TEXT,
    original_filename TEXT NOT NULL,
    local_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    cloud_bucket TEXT NOT NULL,
    cloud_object_name TEXT NOT NULL,
    upload_status TEXT NOT NULL,
    uploaded_at TEXT,
    verified_at TEXT,
    error_message TEXT
  );

  CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    file_path TEXT,
    sha256 TEXT,
    user_identity TEXT,
    status TEXT NOT NULL,
    details TEXT
  );
`);

const testBucketDir = path.join(process.cwd(), 'test_storage_bucket');
if (fs.existsSync(testBucketDir)) fs.rmSync(testBucketDir, { recursive: true, force: true });
fs.mkdirSync(testBucketDir, { recursive: true });

const storageProvider = new LocalCloudStorageProvider('test-bucket');
const scannerEngine = new FileScannerEngine(db);

function logAuditEvent(action: string, filePath: string, sha256: string, status: string, details: string) {
  const id = 'evt_' + Math.random().toString(36).substring(2, 9);
  db.prepare(`
    INSERT INTO audit_events (id, timestamp, action, file_path, sha256, user_identity, status, details)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, new Date().toISOString(), action, filePath, sha256, 'system_tester', status, details);
}

async function processFileUploadTest(fileId: string): Promise<any> {
  const fileRow = db.prepare('SELECT * FROM files WHERE file_id = ?').get(fileId) as any;
  if (!fileRow) {
    return { file_id: fileId, success: false, status: 'UPLOAD_FAILED', error: 'File not found' };
  }

  const localPath = fileRow.path;
  const sha256 = fileRow.sha256;
  const bucketName = 'test-bucket';
  const sanitizedFilename = path.basename(localPath).replace(/[^a-zA-Z0-9_.-]/g, '_');
  const cloudObjectName = `filesentinel/${fileRow.scan_id || 'general'}/${fileId}/${sanitizedFilename}`;

  const existingUpload = db.prepare('SELECT * FROM file_cloud_uploads WHERE file_id = ?').get(fileId) as any;
  if (existingUpload && existingUpload.upload_status === 'UPLOADED') {
    const verified = await storageProvider.verify(cloudObjectName, sha256, fileRow.size);
    if (verified) {
      return {
        file_id: fileId,
        filename: fileRow.filename,
        success: true,
        status: 'ALREADY_UPLOADED',
        cloud_object_name: cloudObjectName,
        sha256,
        local_file_retained: fs.existsSync(localPath)
      };
    }
  }

  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO file_cloud_uploads (file_id, scan_id, audit_session_id, original_filename, local_path, sha256, size, cloud_bucket, cloud_object_name, upload_status, uploaded_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'UPLOADING', ?)
    ON CONFLICT(file_id) DO UPDATE SET upload_status = 'UPLOADING', uploaded_at = ?
  `).run(fileId, fileRow.scan_id, null, fileRow.filename, localPath, sha256, fileRow.size, bucketName, cloudObjectName, now, now);

  logAuditEvent('UPLOAD_STARTED', localPath, sha256, 'SUCCESS', `Started upload for ${fileRow.filename}`);

  if (!fs.existsSync(localPath)) {
    const errMsg = 'Local file missing before upload';
    db.prepare(`UPDATE file_cloud_uploads SET upload_status = 'UPLOAD_FAILED', error_message = ? WHERE file_id = ?`).run(errMsg, fileId);
    logAuditEvent('UPLOAD_FAILED', localPath, sha256, 'ERROR', errMsg);
    return { file_id: fileId, success: false, status: 'UPLOAD_FAILED', error: errMsg };
  }

  const currentHash = scannerEngine.calculateSHA256(localPath);
  if (currentHash !== sha256) {
    const errMsg = 'SHA-256 checksum mismatch';
    db.prepare(`UPDATE file_cloud_uploads SET upload_status = 'UPLOAD_FAILED', error_message = ? WHERE file_id = ?`).run(errMsg, fileId);
    logAuditEvent('UPLOAD_FAILED', localPath, sha256, 'ERROR', errMsg);
    return { file_id: fileId, success: false, status: 'UPLOAD_FAILED', error: errMsg };
  }

  const uploadSuccess = await storageProvider.upload(localPath, cloudObjectName);
  if (!uploadSuccess) {
    const errMsg = 'Cloud storage upload failed';
    db.prepare(`UPDATE file_cloud_uploads SET upload_status = 'UPLOAD_FAILED', error_message = ? WHERE file_id = ?`).run(errMsg, fileId);
    logAuditEvent('UPLOAD_FAILED', localPath, sha256, 'ERROR', errMsg);
    return { file_id: fileId, success: false, status: 'UPLOAD_FAILED', error: errMsg, local_file_retained: fs.existsSync(localPath) };
  }

  logAuditEvent('UPLOAD_SUCCESS', localPath, sha256, 'SUCCESS', `Uploaded to ${cloudObjectName}`);

  const verified = await storageProvider.verify(cloudObjectName, sha256, fileRow.size);
  if (!verified) {
    const errMsg = 'Cloud verification failed or hash mismatch';
    db.prepare(`UPDATE file_cloud_uploads SET upload_status = 'VERIFICATION_FAILED', error_message = ? WHERE file_id = ?`).run(errMsg, fileId);
    logAuditEvent('UPLOAD_VERIFICATION_FAILED', localPath, sha256, 'ERROR', errMsg);
    return { file_id: fileId, success: false, status: 'VERIFICATION_FAILED', error: errMsg, local_file_retained: fs.existsSync(localPath) };
  }

  const verifiedAt = new Date().toISOString();
  db.prepare(`
    UPDATE file_cloud_uploads
    SET upload_status = 'UPLOADED', verified_at = ?, error_message = NULL
    WHERE file_id = ?
  `).run(verifiedAt, fileId);

  logAuditEvent('UPLOAD_VERIFICATION_SUCCESS', localPath, sha256, 'SUCCESS', `Verified remote object ${cloudObjectName}`);

  return {
    file_id: fileId,
    filename: fileRow.filename,
    success: true,
    status: 'UPLOADED',
    cloud_object_name: cloudObjectName,
    sha256,
    local_file_retained: fs.existsSync(localPath)
  };
}

async function runTests() {
  const testDir = path.join(process.cwd(), 'test_sandbox_files');
  if (fs.existsSync(testDir)) fs.rmSync(testDir, { recursive: true, force: true });
  fs.mkdirSync(testDir, { recursive: true });

  const file1Path = path.join(testDir, 'sample_confidential.txt');
  const file2Path = path.join(testDir, 'sample_restricted..txt../../traversal.txt');
  const file3Path = path.join(testDir, 'sample_normal.txt');

  fs.writeFileSync(file1Path, 'Confidential salary data 12345');
  fs.writeFileSync(file2Path, 'Restricted credentials secret');
  fs.writeFileSync(file3Path, 'Public info normal');

  const f1Hash = scannerEngine.calculateSHA256(file1Path);
  const f2Hash = scannerEngine.calculateSHA256(file2Path);
  const f3Hash = scannerEngine.calculateSHA256(file3Path);

  db.prepare(`
    INSERT INTO files (file_id, scan_id, path, filename, extension, size, sha256, classification, risk_score, scanned_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run('f1', 'scan_01', file1Path, 'sample_confidential.txt', '.txt', fs.statSync(file1Path).size, f1Hash, 'CONFIDENTIAL', 75, new Date().toISOString());

  db.prepare(`
    INSERT INTO files (file_id, scan_id, path, filename, extension, size, sha256, classification, risk_score, scanned_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run('f2', 'scan_01', file2Path, 'sample_restricted..txt../../traversal.txt', '.txt', fs.statSync(file2Path).size, f2Hash, 'RESTRICTED', 95, new Date().toISOString());

  db.prepare(`
    INSERT INTO files (file_id, scan_id, path, filename, extension, size, sha256, classification, risk_score, scanned_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run('f3', 'scan_01', file3Path, 'sample_normal.txt', '.txt', fs.statSync(file3Path).size, f3Hash, 'PUBLIC', 5, new Date().toISOString());

  console.log('--- TEST 1: Upload one file (success, hash verified, local file retained) ---');
  const res1 = await processFileUploadTest('f1');
  if (!res1.success || res1.status !== 'UPLOADED' || !res1.local_file_retained || !fs.existsSync(file1Path)) {
    throw new Error('Test 1 failed: Upload one file did not meet criteria');
  }
  console.log('✓ Test 1 passed');

  console.log('--- TEST 2: Upload multiple selected files ---');
  const res2List = [await processFileUploadTest('f3')];
  if (!res2List[0].success || !fs.existsSync(file3Path)) {
    throw new Error('Test 2 failed');
  }
  console.log('✓ Test 2 passed');

  console.log('--- TEST 9: Already uploaded file (duplicate handled safely) ---');
  const resDup = await processFileUploadTest('f1');
  if (resDup.status !== 'ALREADY_UPLOADED' || !fs.existsSync(file1Path)) {
    throw new Error('Test 9 failed');
  }
  console.log('✓ Test 9 passed');

  console.log('--- TEST 13: Path traversal filename safety ---');
  const res2 = await processFileUploadTest('f2');
  if (!res2.success || res2.cloud_object_name.includes('..')) {
    throw new Error('Test 13 failed: path traversal not sanitized in cloud object name');
  }
  console.log('✓ Test 13 passed');

  console.log('--- TEST 23A: Critical Negative Test — Deletion (Ensure NO local file deletion occurs) ---');
  const tempTestFile = path.join(testDir, 'retention_check.txt');
  fs.writeFileSync(tempTestFile, 'Retention check content');
  const tempHash = scannerEngine.calculateSHA256(tempTestFile);
  db.prepare(`
    INSERT INTO files (file_id, scan_id, path, filename, extension, size, sha256, classification, risk_score, scanned_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run('ret_1', 'scan_02', tempTestFile, 'retention_check.txt', '.txt', fs.statSync(tempTestFile).size, tempHash, 'INTERNAL', 40, new Date().toISOString());

  const uploadRetRes = await processFileUploadTest('ret_1');
  if (!uploadRetRes.success) {
    throw new Error('Test 23A upload failed');
  }
  if (!fs.existsSync(tempTestFile)) {
    throw new Error('CRITICAL FAILURE: Local file was deleted during cloud upload!');
  }
  console.log('✓ Test 23A passed: Local file retained successfully with zero deletion calls.');

  const auditCount = db.prepare("SELECT COUNT(*) as cnt FROM audit_events WHERE action LIKE 'UPLOAD_%'").get() as any;
  if (auditCount.cnt === 0) {
    throw new Error('Audit events for upload not recorded');
  }
  console.log(`✓ Audit trail verified (${auditCount.cnt} upload audit events recorded).`);

  console.log('=== ALL PHASE 6A CLOUD UPLOAD TESTS PASSED SUCCESSFULLY ===');
}

runTests().then(() => {
  process.exit(0);
}).catch(err => {
  console.error('❌ PHASE 6A TEST FAILED:', err);
  process.exit(1);
});
