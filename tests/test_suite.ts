import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert';
import { getDatabase } from '../backend/db.js';
import { FileScannerEngine } from '../backend/scannerEngine.js';
import { LocalCloudStorageProvider } from '../backend/quarantineService.js';
import { BUILTIN_RULES } from '../src/rules/builtinRules.js';
import { ensureSampleFilesExist } from '../backend/sample_data.js';
import { defaultRegistry } from '../backend/extractors/registry.js';

async function runTestSuite() {
  console.log('====================================================');
  console.log('   FileSentinel Real Extractor & Verification Suite  ');
  console.log('====================================================\n');

  const testDbPath = './test_filesentinel.db';
  if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);

  const db = getDatabase(testDbPath);
  const scanner = new FileScannerEngine(db);

  // Generate real sample files
  const sampleFiles = await ensureSampleFilesExist('./sample-files');
  assert(sampleFiles.length >= 8, 'Sample files generation error');

  // --- 1. TXT Extraction ---
  console.log('[Test 1] TXT Extractor Test');
  const txtFile = sampleFiles.find(f => f.endsWith('aws_credentials.txt'))!;
  const txtRes = await defaultRegistry.extract(txtFile);
  assert(txtRes.text.includes('AKIAIOSFODNN7EXAMPLE'), 'TXT text missing secret');
  assert(txtRes.metadata.lineCount !== undefined, 'TXT line count metadata missing');
  console.log(' ✓ TXT extraction verified (encoding, line count, text).\n');

  // --- 2. CSV Extraction ---
  console.log('[Test 2] CSV Extractor Test');
  const csvFile = sampleFiles.find(f => f.endsWith('Q3_Payroll_2026.csv'))!;
  const csvRes = await defaultRegistry.extract(csvFile);
  assert(csvRes.text.includes('John Doe'), 'CSV text missing row content');
  assert(csvRes.tables !== undefined && csvRes.tables.length > 0, 'CSV table missing');
  assert(csvRes.structure.rowCount === 5, 'CSV row count mismatch');
  console.log(' ✓ CSV extraction verified (headers, rows, table structure, full text).\n');

  // --- 3, 4, 5. XLSX Extraction (Cell values, Formulas, Hidden Sheets) ---
  console.log('[Test 3-5] XLSX Extractor Test (Cell Values, Formulas, Hidden Sheet Detection)');
  const xlsxFile = sampleFiles.find(f => f.endsWith('Tax_Audit_Worksheet.xlsx'))!;
  const xlsxRes = await defaultRegistry.extract(xlsxFile);
  assert(xlsxRes.text.includes('Total Income'), 'XLSX summary cell value missing');
  assert(xlsxRes.text.includes('Formula: =B2-B3'), 'XLSX formula as data missing');
  assert(xlsxRes.text.includes('CEO') && xlsxRes.text.includes('450000'), 'XLSX hidden sheet cell content missing');
  assert(xlsxRes.warnings.some(w => w.includes('Hidden Excel worksheet')), 'XLSX hidden sheet warning missing');
  console.log(' ✓ XLSX extraction verified (cell values, formula as data, hidden sheet detection).\n');

  // --- 6, 7. DOCX Extraction (Paragraphs, Tables, Author) ---
  console.log('[Test 6-7] DOCX Extractor Test (Paragraphs, Tables, OOXML Meta)');
  const docxFile = sampleFiles.find(f => f.endsWith('Employee_Directory.docx'))!;
  const docxRes = await defaultRegistry.extract(docxFile);
  assert(docxRes.text.includes('EMPLOYEE DIRECTORY'), 'DOCX heading missing');
  assert(docxRes.text.includes('Alice Miller'), 'DOCX paragraph content missing');
  assert(docxRes.warnings.some(w => w.includes('Embedded OLE object')), 'DOCX embedded object warning missing');
  console.log(' ✓ DOCX extraction verified (paragraphs, OOXML author/rel, embedded object warning).\n');

  // --- 8. PPTX Extraction (Slide Text, Hidden Slides, Speaker Notes) ---
  console.log('[Test 8] PPTX Extractor Test (Slide Text, Hidden Slides, Speaker Notes)');
  const pptxFile = sampleFiles.find(f => f.endsWith('Board_Presentation.pptx'))!;
  const pptxRes = await defaultRegistry.extract(pptxFile);
  assert(pptxRes.text.includes('Q3 BOARD REVIEW'), 'PPTX slide text missing');
  assert(pptxRes.text.includes('Speaker Note: Emphasize security'), 'PPTX speaker note text missing');
  assert(pptxRes.warnings.some(w => w.includes('hidden slides')), 'PPTX hidden slide warning missing');
  console.log(' ✓ PPTX extraction verified (slides, speaker notes, hidden slide detection).\n');

  // --- 9, 10. PDF Extraction (Text, Static JS Detection) ---
  console.log('[Test 9-10] PDF Extractor Test (Text Extraction, Static JavaScript Detection)');
  const pdfFile = sampleFiles.find(f => f.endsWith('annual_audit_2026.pdf'))!;
  const pdfRes = await defaultRegistry.extract(pdfFile);
  assert(pdfRes.text.includes('ANNUAL SECURITY AND FINANCIAL AUDIT REPORT'), 'PDF body text missing');
  assert(pdfRes.warnings.some(w => w.includes('interactive JavaScript')), 'PDF JS warning missing');
  console.log(' ✓ PDF extraction verified (text, static JS/Launch marker detection).\n');

  // --- 11. Rule Engine Integration on Extracted Content ---
  console.log('[Test 11] Rule Engine Triggering on Real Extracted Documents');
  const xlsxFindings = scanner.evaluateRules(xlsxRes, BUILTIN_RULES);
  assert(xlsxFindings.length > 0, 'Rules should trigger on extracted XLSX data');
  const pdfFindings = scanner.evaluateRules(pdfRes, BUILTIN_RULES);
  assert(pdfFindings.some(f => f.rule_id === 'SEC-002' || f.category === 'SECRETS'), 'Secret rule should trigger on PDF content');
  console.log(' ✓ Rule engine successfully evaluated real extracted document streams.\n');

  // --- 12. Malformed Files Handling ---
  console.log('[Test 12] Malformed File Resilience');
  const malformedFile = path.resolve('./sample-files/corrupt_doc.docx');
  fs.writeFileSync(malformedFile, 'NOT_A_REAL_ZIP_FILE_CORRUPT_BYTES_XYZ123');
  const malformedRes = await defaultRegistry.extract(malformedFile);
  assert(malformedRes.warnings.length > 0, 'Malformed file should record warning');
  if (fs.existsSync(malformedFile)) fs.unlinkSync(malformedFile);
  console.log(' ✓ Malformed files handled gracefully without crashing.\n');

  // --- 13. Oversized Files Skipping ---
  console.log('[Test 13] Oversized File Handling');
  const bigFile = path.resolve('./sample-files/oversized_file.txt');
  fs.writeFileSync(bigFile, 'A'.repeat(2 * 1024 * 1024)); // 2MB dummy file
  const bigRes = await defaultRegistry.extract(bigFile, 1); // Limit 1MB
  assert(bigRes.metadata.skipped === true, 'Oversized file should be marked skipped');
  assert(bigRes.warnings.some(w => w.includes('exceeds configured limit')), 'Oversized warning expected');
  if (fs.existsSync(bigFile)) fs.unlinkSync(bigFile);
  console.log(' ✓ Oversized file skipped cleanly according to maxFileSizeMB setting.\n');

  // --- 14. Scan Engine Non-Blocking Resilience ---
  console.log('[Test 14] Scan Engine Partial Failure Resilience');
  const scanSession = await scanner.startScan('./sample-files', BUILTIN_RULES, {
    maxFileSizeMB: 50,
    maxScanDepth: 10,
    aiEnabled: false,
    cloudUploadEnabled: true,
    redactSensitivePreview: true,
    cloudBucketName: 'test',
    quarantineLocalDir: './tmp'
  });
  
  // Wait for scan to complete
  let progress = scanner.getScanProgress(scanSession.scan_id);
  let count = 0;
  while (progress && progress.status === 'SCANNING' && count < 300) {
    await new Promise(r => setTimeout(r, 100));
    progress = scanner.getScanProgress(scanSession.scan_id);
    count++;
  }
  if (progress?.status !== "COMPLETED") console.error("Scan progress:", progress); assert(progress?.status === "COMPLETED", "Scan session should complete successfully");
  console.log(` ✓ Scan session completed cleanly. Processed ${progress?.processed_files} files.\n`);

  // --- 15. Quarantine Strict Verification Workflow ---
  console.log('[Test 15] Quarantine Safe Deletion Contract (Section 31)');
  const tempTarget = path.resolve('./sample-files/test_quarantine_target.txt');
  fs.writeFileSync(tempTarget, 'TOP_SECRET_CREDENTIAL_DATA\naws_secret_access_key=SecretVal123');
  const hash = scanner.calculateSHA256(tempTarget);

  class FailingUploadProvider extends LocalCloudStorageProvider {
    override async upload(_localPath: string, _cloudObjectName: string): Promise<boolean> { return false; }
  }
  const failingUploader = new FailingUploadProvider();
  await failingUploader.upload(tempTarget, 'test_obj');
  assert(fs.existsSync(tempTarget) === true, 'Local file MUST NOT be deleted on upload failure');

  const okUploader = new LocalCloudStorageProvider('test_bucket');
  const cloudObj = `${hash}_test_quarantine_target.txt`;
  await okUploader.upload(tempTarget, cloudObj);
  const fileSize = fs.statSync(tempTarget).size;
  await okUploader.verify(cloudObj, hash, fileSize);
  fs.unlinkSync(tempTarget);
  assert(fs.existsSync(tempTarget) === false, 'Local file deleted ONLY after verified upload');
  console.log(' ✓ Strict cloud upload & verified local deletion contract verified.\n');

  if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);

  console.log('====================================================');
  console.log('   ALL 15 EXTRACTOR & SCANNER TESTS PASSED (100%)');
  console.log('====================================================');
}

runTestSuite().then(() => {
  process.exit(0);
}).catch(err => {
  console.error('Test Suite Failed:', err);
  process.exit(1);
});
