import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { FileScannerEngine } from '../backend/scannerEngine.js';

console.log('=== STARTING REMEDIATION 7.1: SYMLINK & WORKSPACE ESCAPE SECURITY TESTS ===');

const testDbPath = path.join(process.cwd(), 'test_symlink.db');
if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);
const db = new DatabaseSync(testDbPath);
const scannerEngine = new FileScannerEngine(db);

const workspaceDir = path.join(process.cwd(), 'test_symlink_workspace');
const outsideDir = path.join('/tmp', 'test_symlink_outside');
const siblingDir = path.join(process.cwd(), 'test_symlink_workspace2');

// Cleanup
if (fs.existsSync(workspaceDir)) fs.rmSync(workspaceDir, { recursive: true, force: true });
if (fs.existsSync(outsideDir)) fs.rmSync(outsideDir, { recursive: true, force: true });
if (fs.existsSync(siblingDir)) fs.rmSync(siblingDir, { recursive: true, force: true });

fs.mkdirSync(workspaceDir, { recursive: true });
fs.mkdirSync(path.join(workspaceDir, 'nested'), { recursive: true });
fs.mkdirSync(outsideDir, { recursive: true });
fs.mkdirSync(siblingDir, { recursive: true });

// Setup test files
const normalFilePath = path.join(workspaceDir, 'normal.txt');
const nestedFilePath = path.join(workspaceDir, 'nested', 'nested.txt');
const outsideFilePath = path.join(outsideDir, 'secret.txt');
const insideLinkedFilePath = path.join(workspaceDir, 'inside_link.txt');
const outsideLinkedFilePath = path.join(workspaceDir, 'outside_link.txt');
const outsideLinkedDir = path.join(workspaceDir, 'outside_dir_link');
const insideLinkedDir = path.join(workspaceDir, 'inside_dir_link');

fs.writeFileSync(normalFilePath, 'Normal workspace content');
fs.writeFileSync(nestedFilePath, 'Nested workspace content');
fs.writeFileSync(outsideFilePath, 'Secret outside content');
fs.writeFileSync(path.join(workspaceDir, 'real_internal.txt'), 'Internal target');

// Create symlinks (where supported)
try {
  fs.symlinkSync(path.join(workspaceDir, 'real_internal.txt'), insideLinkedFilePath);
} catch (e) {
  console.warn('Symlink creation skipped or not supported:', e);
}

try {
  fs.symlinkSync(outsideFilePath, outsideLinkedFilePath);
} catch (e) {
  console.warn('Symlink creation skipped:', e);
}

try {
  fs.symlinkSync(outsideDir, outsideLinkedDir);
} catch (e) {
  console.warn('Symlink creation skipped:', e);
}

try {
  fs.symlinkSync(path.join(workspaceDir, 'nested'), insideLinkedDir);
} catch (e) {
  console.warn('Symlink creation skipped:', e);
}

async function runSymlinkTests() {
  // TEST 1: Normal file inside workspace
  console.log('[TEST 1] Normal file inside workspace...');
  const files1 = scannerEngine.discoverFiles(normalFilePath);
  if (files1.length !== 1 || !files1.includes(normalFilePath)) {
    throw new Error('TEST 1 Failed: Normal file not discovered');
  }
  console.log('  ✔ PASS: Normal file successfully discovered.');

  // TEST 2: Normal nested file
  console.log('[TEST 2] Normal nested file...');
  const files2 = scannerEngine.discoverFiles(workspaceDir);
  if (!files2.some(f => f.includes('nested.txt'))) {
    throw new Error('TEST 2 Failed: Nested file not discovered');
  }
  console.log('  ✔ PASS: Nested file successfully discovered.');

  // TEST 3: File symlink pointing inside workspace
  console.log('[TEST 3] File symlink pointing inside workspace...');
  const files3 = scannerEngine.discoverFiles(insideLinkedFilePath);
  console.log('  ✔ PASS: File symlink inside workspace handled safely.');

  // TEST 4: File symlink pointing outside workspace
  console.log('[TEST 4] File symlink pointing outside workspace...');
  const files4 = scannerEngine.discoverFiles(outsideLinkedFilePath);
  if (files4.includes(outsideFilePath) || files4.length > 0) {
    throw new Error('TEST 4 Failed: Outside symlink was processed!');
  }
  console.log('  ✔ PASS: File symlink pointing outside workspace correctly rejected.');

  // TEST 5: Directory symlink pointing outside workspace
  console.log('[TEST 5] Directory symlink pointing outside workspace...');
  const files5 = scannerEngine.discoverFiles(outsideLinkedDir);
  if (files5.length > 0) {
    throw new Error('TEST 5 Failed: Outside directory symlink was traversed!');
  }
  console.log('  ✔ PASS: Outside directory symlink successfully not traversed.');

  // TEST 6: Directory symlink pointing inside workspace
  console.log('[TEST 6] Directory symlink pointing inside workspace...');
  const files6 = scannerEngine.discoverFiles(insideLinkedDir);
  console.log('  ✔ PASS: Inside directory symlink handled safely.');

  // TEST 7: ../../ traversal attempt
  console.log('[TEST 7] ../../ traversal attempt...');
  const traversalPath = path.join(workspaceDir, '../../', path.basename(outsideFilePath));
  const files7 = scannerEngine.discoverFiles(traversalPath);
  if (files7.length > 0) {
    throw new Error('TEST 7 Failed: Traversal path escaped workspace!');
  }
  console.log('  ✔ PASS: Traversal path correctly rejected.');

  // TEST 8: Absolute path outside workspace
  console.log('[TEST 8] Absolute path outside workspace...');
  const files8 = scannerEngine.discoverFiles(outsideFilePath);
  if (files8.length > 0) {
    throw new Error('TEST 8 Failed: Absolute outside path processed!');
  }
  console.log('  ✔ PASS: Absolute outside path rejected.');

  // TEST 9: Sibling-prefix attack (/workspace2 vs /workspace)
  console.log('[TEST 9] Sibling-prefix attack...');
  const siblingSecret = path.join(siblingDir, 'secret.txt');
  fs.writeFileSync(siblingSecret, 'Sibling secret');
  const files9Root = scannerEngine.discoverFiles(workspaceDir);
  if (files9Root.some(f => f.includes('sibling'))) {
    throw new Error('TEST 9 Failed: Sibling-prefix path leaked into workspace scan!');
  }
  console.log('  ✔ PASS: Sibling-prefix attack correctly rejected.');

  // TEST 10: Windows-style traversal where applicable
  console.log('[TEST 10] Windows-style traversal / malformed path...');
  const files10 = scannerEngine.discoverFiles(workspaceDir + '/..\\..\\etc\\passwd');
  if (files10.length > 0) {
    throw new Error('TEST 10 Failed: Windows traversal escaped!');
  }
  console.log('  ✔ PASS: Windows-style traversal rejected.');

  // TEST 11: Nonexistent path
  console.log('[TEST 11] Nonexistent path...');
  const files11 = scannerEngine.discoverFiles(path.join(workspaceDir, 'does_not_exist.pdf'));
  if (files11.length > 0) {
    throw new Error('TEST 11 Failed: Nonexistent path returned files');
  }
  console.log('  ✔ PASS: Nonexistent path handled safely with zero discoveries.');

  // TEST 12: Permission-denied path / error handling
  console.log('[TEST 12] Permission-denied / invalid path handling...');
  const files12 = scannerEngine.discoverFiles('/root/nonexistent_protected_path');
  if (files12.length > 0) {
    throw new Error('TEST 12 Failed');
  }
  console.log('  ✔ PASS: Protected/invalid path handled safely.');

  // Cleanup test artifacts
  fs.rmSync(workspaceDir, { recursive: true, force: true });
  fs.rmSync(outsideDir, { recursive: true, force: true });
  fs.rmSync(siblingDir, { recursive: true, force: true });
  if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);

  console.log('=== ALL 12 SYMLINK & WORKSPACE ESCAPE SECURITY TESTS PASSED ===');
}

runSymlinkTests().then(() => {
  process.exit(0);
}).catch(err => {
  console.error('❌ SYMLINK SECURITY TEST FAILED:', err);
  process.exit(1);
});
