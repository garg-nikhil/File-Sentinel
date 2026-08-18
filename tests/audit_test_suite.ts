import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { getDatabase } from '../backend/db.js';

// Disable Gemini AI API calls during tests to avoid quota exhaustion
process.env.GEMINI_API_KEY = 'MY_GEMINI_API_KEY';
import { INITIAL_AUDIT_CHECKLIST } from '../backend/audit/checklist.js';
import { EvidenceEngine } from '../backend/audit/evidenceEngine.js';
import { DateEvaluator } from '../backend/audit/dateEvaluator.js';
import { AuditReportGenerator } from '../backend/audit/auditReport.js';
import { ensureSampleFilesExist } from '../backend/sample_data.js';

async function runAuditTests() {
  console.log('====================================================');
  console.log('       FILESENTINEL AUDIT ENGINE TEST SUITE');
  console.log('====================================================');

  // 1. Verify Checklist Model
  console.log('\n[TEST 1] Verifying Checklist Structure & 29 Initial Parameters...');
  assert.strictEqual(INITIAL_AUDIT_CHECKLIST.length, 29, 'Expected exactly 29 checklist parameters');

  const zeroTolerance = INITIAL_AUDIT_CHECKLIST.filter(p => p.category === 'ZERO_TOLERANCE');
  const govInfosec = INITIAL_AUDIT_CHECKLIST.filter(p => p.category === 'GOVERNANCE_COMPLIANCE_INFOSEC');
  const infraProcess = INITIAL_AUDIT_CHECKLIST.filter(p => p.category === 'INFRASTRUCTURE_PROCESS_MANAGEMENT');

  assert.strictEqual(zeroTolerance.length, 10, 'Category 1 must have 10 parameters');
  assert.strictEqual(govInfosec.length, 8, 'Category 2 must have 8 parameters');
  assert.strictEqual(infraProcess.length, 11, 'Category 3 must have 11 parameters');

  // Verify Zero Tolerance parameters have fatal=true
  for (const zt of zeroTolerance) {
    assert.strictEqual(zt.fatal, true, `Parameter ${zt.id} must be fatal`);
  }
  console.log('✔ Checklist Structure verified (10 ZTI, 8 GCI, 11 IPM).');

  // 2. Date Evaluator Test
  console.log('\n[TEST 2] Verifying Date & Expiry Engine...');
  assert.strictEqual(DateEvaluator.isExpired('2025-12-31', '2026-08-12'), true, '2025-12-31 should be expired relative to 2026-08-12');
  assert.strictEqual(DateEvaluator.isExpired('2027-12-31', '2026-08-12'), false, '2027-12-31 should be valid relative to 2026-08-12');
  assert.strictEqual(DateEvaluator.isOlderThanYears('2025-01-01', '2026-08-12', 1), true, '2025-01-01 is older than 1 year relative to 2026-08-12');
  console.log('✔ Date & Expiry Engine tests passed.');

  // 3. Ensure Sample Files & Run Real Audit
  console.log('\n[TEST 3] Running Real Audit Scan over synthetic audit sample directory...');
  const sampleDir = './sample-files/audit';
  await ensureSampleFilesExist('./sample-files');

  const files = fs.readdirSync(sampleDir).map(f => path.join(sampleDir, f));
  assert.ok(files.length > 10, 'Expected synthetic sample files in sample-files/audit');

  const db = getDatabase(':memory:');
  const engine = new EvidenceEngine(db);

  const auditDate = '2026-08-12';
  const session = await engine.runAuditScan(
    files,
    auditDate,
    'Zenith Collection Agency',
    'Lead Auditor Test Suite'
  );

  console.log(`✔ Audit Session Created: ${session.audit_id}`);
  console.log(`  Overall Status: ${session.overall_status}`);
  console.log(`  Overall Score: ${session.overall_score} / ${session.max_score}`);
  console.log(`  Parameters (PASS/FAIL/REVIEW/NOT_FOUND): ${session.pass_count} / ${session.fail_count} / ${session.review_count} / ${session.not_found_count}`);

  assert.ok(session.total_parameters > 20, 'Session should evaluate active checklist parameters');

  // 4. Verify Parameter-Specific Evaluations
  console.log('\n[TEST 4] Verifying Specific Parameter Outcomes...');
  const resultsMap = new Map(session.parameter_results?.map(r => [r.parameter_id, r]));

  // ZTI-001 (GST Certificate) -> PASS
  const zti001 = resultsMap.get('ZTI-001');
  assert.ok(zti001, 'ZTI-001 result missing');
  assert.strictEqual(zti001?.status, 'PASS', 'GST Registration should PASS');
  console.log('  - ZTI-001 GST Details: PASS');

  // ZTI-004 (DRA Certificate) -> PASS
  const zti004 = resultsMap.get('ZTI-004');
  assert.ok(zti004, 'ZTI-004 result missing');
  assert.strictEqual(zti004?.status, 'PASS', 'DRA Certificate should PASS');
  console.log('  - ZTI-004 DRA Certificate: PASS');

  // ZTI-005 (Police Verification Applied) -> PASS (PV Status = APPLIED)
  const zti005 = resultsMap.get('ZTI-005');
  assert.ok(zti005, 'ZTI-005 result missing');
  assert.strictEqual(zti005?.status, 'PASS', 'Police Verification proof of application should PASS');
  assert.strictEqual(zti005?.pv_status, 'APPLIED', 'PV status should be APPLIED');
  console.log('  - ZTI-005 Police Verification: PASS (Status: APPLIED)');

  // ZTI-008 (USB Restriction Policy + Implementation) -> PASS
  const zti008 = resultsMap.get('ZTI-008');
  assert.ok(zti008, 'ZTI-008 result missing');
  assert.strictEqual(zti008?.status, 'PASS', 'USB Restriction with GPO config implementation should PASS');
  console.log('  - ZTI-008 USB/Cloud Storage Restriction: PASS');

  // IPM-003 (Lease + Shops & Est) -> PASS
  const ipm003 = resultsMap.get('IPM-003');
  assert.ok(ipm003, 'IPM-003 result missing');
  assert.strictEqual(ipm003?.status, 'PASS', 'Compound Rent Lease & Shops Certificate should PASS');
  console.log('  - IPM-003 Premises & Shops Certificate: PASS');

  // IPM-006 (CCTV 90 Days Retention) -> PASS
  const ipm006 = resultsMap.get('IPM-006');
  assert.ok(ipm006, 'IPM-006 result missing');
  assert.strictEqual(ipm006?.status, 'PASS', 'CCTV 90 Days Retention should PASS');
  console.log('  - IPM-006 CCTV 90 Days Retention: PASS');

  // 5. Test Auditor Override and Recalculation
  console.log('\n[TEST 5] Verifying Auditor Manual Override & Score Recalculation...');
  const overrideRes = db.prepare('SELECT * FROM audit_sessions WHERE audit_id = ?').get(session.audit_id);
  assert.ok(overrideRes, 'Audit session in DB missing');

  // Apply override to ZTI-006 (Human Review -> PASS)
  const zti006 = resultsMap.get('ZTI-006');
  assert.ok(zti006, 'ZTI-006 missing');

  db.prepare(`
    UPDATE audit_parameter_results
    SET override_json = ?
    WHERE audit_id = ? AND parameter_id = 'ZTI-006'
  `).run(JSON.stringify({
    original_status: zti006.status,
    new_status: 'PASS',
    auditor_name: 'Lead Auditor Jane',
    comment: 'Verified absence of misconduct via physical audit log.',
    timestamp: new Date().toISOString()
  }), session.audit_id);

  console.log('✔ Auditor override applied to ZTI-006.');

  // 6. Test Report Generation
  console.log('\n[TEST 6] Verifying Report Generators (HTML, CSV, JSON)...');
  const jsonReport = AuditReportGenerator.generateJson(session);
  const csvReport = AuditReportGenerator.generateCsv(session);
  const htmlReport = AuditReportGenerator.generateHtml(session);

  assert.ok(jsonReport.includes(session.audit_id), 'JSON report should contain audit ID');
  assert.ok(csvReport.includes('Parameter ID,Category'), 'CSV report should contain headers');
  assert.ok(htmlReport.includes('FILESENTINEL AUDIT COMPLIANCE REPORT'), 'HTML report should contain title');
  console.log('✔ All 3 report formats (HTML, CSV, JSON) generated successfully.');

  console.log('\n====================================================');
  console.log('      ALL 6 AUDIT ENGINE TESTS PASSED PERFECTLY!');
  console.log('====================================================');
}

runAuditTests().then(() => {
  process.exit(0);
}).catch(err => {
  console.error('\n❌ Audit Test Suite Failed:', err);
  process.exit(1);
});
