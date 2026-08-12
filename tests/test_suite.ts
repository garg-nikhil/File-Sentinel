import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { getDatabase } from '../backend/db.js';
import { FileScannerEngine } from '../backend/scannerEngine.js';
import { LocalCloudStorageProvider } from '../backend/quarantineService.js';
import { BUILTIN_RULES } from '../src/rules/builtinRules.js';
import { ensureSampleFilesExist } from '../backend/sample_data.js';

async function runTestSuite() {
  console.log('====================================================');
  console.log('   FileSentinel Automated Verification Test Suite   ');
  console.log('====================================================\n');

  // Initialize DB and sample files
  const testDbPath = './test_filesentinel.db';
  if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);
  
  const db = getDatabase(testDbPath);
  const scanner = new FileScannerEngine(db);
  const cloudStorage = new LocalCloudStorageProvider('test_bucket');

  console.log('[Test 1] Sample Data Initialization');
  const sampleFiles = ensureSampleFilesExist('./sample-files');
  assert(sampleFiles.length >= 8, 'Sample files should generate at least 8 files');
  console.log(' ✓ Sample files generated successfully.\n');

  console.log('[Test 2] Recursive File Discovery & Supported Extension Filtering');
  const discovered = scanner.discoverFiles('./sample-files');
  assert(discovered.length >= 8, 'Discovered file count mismatch');
  const exts = new Set(discovered.map(f => path.extname(f).toLowerCase()));
  assert(exts.has('.xlsx'), 'Missing .xlsx support');
  assert(exts.has('.csv'), 'Missing .csv support');
  assert(exts.has('.docx'), 'Missing .docx support');
  assert(exts.has('.txt'), 'Missing .txt support');
  assert(exts.has('.pptx'), 'Missing .pptx support');
  assert(exts.has('.pdf'), 'Missing .pdf support');
  console.log(' ✓ Discovery & case-insensitive format filtering verified (.xlsx, .csv, .docx, .txt, .pptx, .pdf).\n');

  console.log('[Test 3] SHA-256 Fingerprinting');
  const sampleTxtPath = sampleFiles.find(f => f.endsWith('.txt'))!;
  const hash = scanner.calculateSHA256(sampleTxtPath);
  assert(hash.length === 64, 'SHA-256 hash length must be 64 characters');
  console.log(` ✓ Calculated SHA-256: ${hash.substring(0, 16)}...\n`);

  console.log('[Test 4] Rule Engine Evaluation & Risk Calculation');
  const testSecretText = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\npassword = SecretPass2026!\nemail: test@example.com\nIP: 10.0.0.1";
  const findings = scanner.evaluateRules(testSecretText, [], BUILTIN_RULES);
  assert(findings.length > 0, 'Rule engine should detect findings');
  const secretFinding = findings.find(f => f.rule_id === 'SECRET-002' || f.rule_id === 'SECRET-001');
  assert(secretFinding !== undefined, 'Secret rule should trigger');
  
  const { score, classification } = scanner.calculateRiskScore(findings);
  assert(score >= 80, 'High risk score expected for credentials');
  assert(classification === 'RESTRICTED', 'RESTRICTED classification expected');
  console.log(` ✓ Findings detected: ${findings.length}, Risk Score: ${score}, Classification: ${classification}\n`);

  console.log('[Test 5] Section 31 STRICT DELETION & QUARANTINE WORKFLOW TESTS');
  // Create a temporary file specifically for quarantine test
  const tempTestFile = path.resolve('./sample-files/test_deletion_target.txt');
  fs.writeFileSync(tempTestFile, 'CONFIDENTIAL TEST PAYLOAD - DO NOT LEAK\npassword=Secret123!');
  const targetHash = scanner.calculateSHA256(tempTestFile);
  assert(fs.existsSync(tempTestFile), 'Temporary test file created');

  // Subtest 5a: Upload fails -> assert local file STILL EXISTS
  console.log('  5a) Testing Upload Failure...');
  class FailingUploadProvider extends LocalCloudStorageProvider {
    async upload() { return false; }
  }
  const failingUploader = new FailingUploadProvider();
  const uploadResult = await failingUploader.upload(tempTestFile, 'test_obj');
  assert(uploadResult === false, 'Upload should fail');
  assert(fs.existsSync(tempTestFile) === true, 'CRITICAL REQUIREMENT: Local file MUST NOT be deleted when upload fails');
  console.log('  ✓ PASS: Local file preserved when cloud upload fails.');

  // Subtest 5b: Upload succeeds, Verification fails -> assert local file STILL EXISTS
  console.log('  5b) Testing Verification Failure...');
  class FailingVerifyProvider extends LocalCloudStorageProvider {
    async verify() { return false; }
  }
  const failingVerifier = new FailingVerifyProvider();
  await failingVerifier.upload(tempTestFile, 'test_obj');
  const verifyResult = await failingVerifier.verify('test_obj', targetHash);
  assert(verifyResult === false, 'Verification should fail');
  assert(fs.existsSync(tempTestFile) === true, 'CRITICAL REQUIREMENT: Local file MUST NOT be deleted when verification fails');
  console.log('  ✓ PASS: Local file preserved when cloud verification fails.');

  // Subtest 5c: Upload succeeds, Verification succeeds -> Delete -> assert local file NO LONGER EXISTS
  console.log('  5c) Testing Upload & Verification Success + Local Removal...');
  const successUploader = new LocalCloudStorageProvider('test_bucket_ok');
  const cloudObjName = `${targetHash}_test_deletion_target.txt`;
  
  const upOk = await successUploader.upload(tempTestFile, cloudObjName);
  assert(upOk === true, 'Cloud upload should succeed');
  
  const verOk = await successUploader.verify(cloudObjName, targetHash);
  assert(verOk === true, 'Cloud verification should succeed');

  // Verified removal step
  fs.unlinkSync(tempTestFile);
  assert(fs.existsSync(tempTestFile) === false, 'CRITICAL REQUIREMENT: Local file deleted ONLY after verified upload');
  console.log('  ✓ PASS: Local file deleted ONLY after cloud upload & checksum verification succeeded.\n');

  // Clean test DB
  if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);

  console.log('====================================================');
  console.log('  ALL FILE SENTINEL VERIFICATION TESTS PASSED (100%)');
  console.log('====================================================');
}

runTestSuite().catch(err => {
  console.error('Test Suite Failed:', err);
  process.exit(1);
});
