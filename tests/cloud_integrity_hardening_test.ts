import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { LocalCloudStorageProvider } from '../backend/quarantineService.js';

async function runCloudIntegrityHardeningTests() {
  console.log('================================================================');
  console.log('   FileSentinel Cloud Integrity Hardening Test Suite (Phase 7.x)  ');
  console.log('================================================================');

  const bucketName = 'integrity_test_bucket';
  const provider = new LocalCloudStorageProvider(bucketName);
  const tempDir = path.resolve('./test_integrity_temp');
  if (fs.existsSync(tempDir)) fs.rmSync(tempDir, { recursive: true, force: true });
  fs.mkdirSync(tempDir, { recursive: true });

  const testFile = path.join(tempDir, 'test.txt');
  const fileContent = 'Integrity test content for FileSentinel cloud verification.';
  fs.writeFileSync(testFile, fileContent);
  const correctSha256 = crypto.createHash('sha256').update(fileContent).digest('hex');
  const correctSize = fs.statSync(testFile).size;
  const cloudObjectName = 'integrity_test_obj.txt';

  // Upload object
  const uploaded = await provider.upload(testFile, cloudObjectName);
  assert.strictEqual(uploaded, true, 'Upload should succeed');

  let passed = 0;
  let failed = 0;

  try {
    // 1. matching SHA + matching size → PASS
    const r1 = await provider.verify(cloudObjectName, correctSha256, correctSize);
    assert.strictEqual(r1, true, 'matching SHA + matching size should PASS');
    console.log('  ✔ [TEST 1] matching SHA + matching size → PASS');
    passed++;
  } catch (e: any) {
    console.error('  ✘ [TEST 1] Failed:', e.message);
    failed++;
  }

  try {
    // 2. matching SHA + wrong size → FAIL
    const r2 = await provider.verify(cloudObjectName, correctSha256, correctSize + 999);
    assert.strictEqual(r2, false, 'matching SHA + wrong size should FAIL');
    console.log('  ✔ [TEST 2] matching SHA + wrong size → FAIL');
    passed++;
  } catch (e: any) {
    console.error('  ✘ [TEST 2] Failed:', e.message);
    failed++;
  }

  try {
    // 3. matching SHA + missing size (e.g. 0 or negative or invalid expected size) → FAIL
    const r3 = await provider.verify(cloudObjectName, correctSha256, 0);
    assert.strictEqual(r3, false, 'matching SHA + missing/zero size should FAIL');
    console.log('  ✔ [TEST 3] matching SHA + missing/zero size → FAIL');
    passed++;
  } catch (e: any) {
    console.error('  ✘ [TEST 3] Failed:', e.message);
    failed++;
  }

  try {
    // 4. wrong SHA + matching size → FAIL
    const r4 = await provider.verify(cloudObjectName, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', correctSize);
    assert.strictEqual(r4, false, 'wrong SHA + matching size should FAIL');
    console.log('  ✔ [TEST 4] wrong SHA + matching size → FAIL');
    passed++;
  } catch (e: any) {
    console.error('  ✘ [TEST 4] Failed:', e.message);
    failed++;
  }

  try {
    // 5. missing SHA -> In LocalCloudStorageProvider, getMetadata computes SHA from file, but what if we test a custom mock or check missing remote metadata behavior?
    // Wait, let's test missing remote object → FAIL
    const r6 = await provider.verify('non_existent_object.txt', correctSha256, correctSize);
    assert.strictEqual(r6, false, 'missing remote object should FAIL');
    console.log('  ✔ [TEST 6] missing remote object → FAIL');
    passed++;
  } catch (e: any) {
    console.error('  ✘ [TEST 6] Failed:', e.message);
    failed++;
  }

  // Also test missing SHA metadata case specifically by subclassing / mocking getMetadata or testing GoogleCloudStorageProvider / custom provider
  class MissingShaProvider extends LocalCloudStorageProvider {
    override async getMetadata(_objName: string) {
      return { exists: true, size: correctSize }; // sha256 missing
    }
  }
  const missingShaProv = new MissingShaProvider(bucketName);
  try {
    const r5 = await missingShaProv.verify(cloudObjectName, correctSha256, correctSize);
    assert.strictEqual(r5, false, 'missing SHA + matching size should FAIL');
    console.log('  ✔ [TEST 5] missing SHA + matching size → FAIL');
    passed++;
  } catch (e: any) {
    console.error('  ✘ [TEST 5] Failed:', e.message);
    failed++;
  }

  // Cleanup
  await provider.deleteRemote(cloudObjectName);
  if (fs.existsSync(tempDir)) fs.rmSync(tempDir, { recursive: true, force: true });

  console.log('================================================================');
  console.log(`  RESULTS: ${passed} Passed, ${failed} Failed`);
  console.log('================================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

runCloudIntegrityHardeningTests().then(() => {
  process.exit(0);
}).catch(err => {
  console.error('Cloud Integrity Hardening Test Suite Failed:', err);
  process.exit(1);
});
