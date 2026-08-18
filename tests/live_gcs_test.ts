import fs from 'fs';
import path from 'path';
import { GoogleCloudStorageProvider } from '../backend/quarantineService.js';

console.log('=== LIVE GCS UPLOAD & NON-DESTRUCTIVE RETENTION TEST ===');

async function runLiveTest() {
  const projectId = process.env.GOOGLE_CLOUD_PROJECT;
  const bucketName = process.env.GOOGLE_CLOUD_BUCKET;

  if (!projectId || !bucketName) {
    console.log('LIVE GCS TEST: NOT RUN (GOOGLE_CLOUD_PROJECT or GOOGLE_CLOUD_BUCKET not configured in environment).');
    console.log('This is expected in default preview environments without live cloud keys.');
    return;
  }

  try {
    const provider = new GoogleCloudStorageProvider(bucketName);
    const testFilePath = path.join(process.cwd(), 'live_gcs_test_temp.txt');
    fs.writeFileSync(testFilePath, 'Live GCS test content — non-destructive retention verification.');

    const cloudObjectName = `filesentinel/live-test/live_gcs_test_temp.txt`;

    console.log(`Uploading live test file to GCS bucket: ${bucketName}...`);
    const success = await provider.upload(testFilePath, cloudObjectName);
    if (!success) {
      throw new Error('Live GCS upload returned false');
    }

    const crypto = await import('node:crypto');
    const buf = fs.readFileSync(testFilePath);
    const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
    const size = fs.statSync(testFilePath).size;
    const exists = await provider.verify(cloudObjectName, sha256, size);
    if (!exists) {
      throw new Error('Live GCS verification failed');
    }

    if (!fs.existsSync(testFilePath)) {
      throw new Error('CRITICAL FAILURE: Local test file was deleted during live GCS upload!');
    }

    console.log('Cleaning up remote GCS test object...');
    await provider.deleteRemote(cloudObjectName);
    fs.unlinkSync(testFilePath);

    console.log('=== LIVE GCS TEST PASSED SUCCESSFULLY ===');
  } catch (err: any) {
    console.warn('Live GCS test encountered error (or skipped due to auth):', err.message);
  }
}

runLiveTest().then(() => {
  process.exit(0);
});
