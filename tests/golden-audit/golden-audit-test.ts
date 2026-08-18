import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert';
import { getDatabase } from '../../backend/db.js';

// Disable Gemini AI API calls during tests to avoid quota exhaustion
process.env.GEMINI_API_KEY = 'MY_GEMINI_API_KEY';
import { defaultRegistry } from '../../backend/extractors/registry.js';
import { EvidenceEngine } from '../../backend/audit/evidenceEngine.js';
import { EvidenceMatcher } from '../../backend/audit/evidenceMatcher.js';
import { AuditEvaluator } from '../../backend/audit/evaluator.js';
import { DateEvaluator } from '../../backend/audit/dateEvaluator.js';
import { INITIAL_AUDIT_CHECKLIST } from '../../backend/audit/checklist.js';
import { generateGoldenDataset } from './generate-dataset.js';

async function runGoldenAuditTestSuite() {
  console.log('================================================================');
  console.log('  FileSentinel Golden Multi-Format End-to-End Audit Test Suite  ');
  console.log('================================================================\n');

  const docsDir = path.resolve('./tests/golden-audit/documents');
  const manifestPath = path.resolve('./tests/golden-audit/dataset-manifest.json');
  const expectedResultsPath = path.resolve('./tests/golden-audit/expected-results.json');

  // STEP 1: Generate Golden Dataset
  console.log('[STEP 1] Generating Real Multi-Format Synthetic Documents...');
  const generatedFiles = await generateGoldenDataset(docsDir);
  assert.ok(generatedFiles.length >= 30, `Expected at least 30 documents, generated ${generatedFiles.length}`);
  console.log(`  ✔ Successfully generated ${generatedFiles.length} synthetic files in ${docsDir}\n`);

  // Verify dataset manifest and expected results exist
  assert.ok(fs.existsSync(manifestPath), 'dataset-manifest.json must exist');
  assert.ok(fs.existsSync(expectedResultsPath), 'expected-results.json must exist');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
  const expectedResults = JSON.parse(fs.readFileSync(expectedResultsPath, 'utf-8'));

  // STEP 2: Format-by-Format Direct Extractor Verification
  console.log('[STEP 2] Verifying Real Document Extraction Across All 6 Formats...');

  // 2.1 PDF Extractor
  const pdfFile = path.join(docsDir, 'GST_Registration_Certificate.pdf');
  const pdfRes = await defaultRegistry.extract(pdfFile);
  assert.ok(pdfRes.text.includes('27SYNTHETIC0000Z0'), 'PDF extraction missing GSTIN text');
  assert.ok(pdfRes.text.includes('Sentinel Recovery'), 'PDF extraction missing legal name');
  console.log('  ✔ [PDF] Real PDF extracted cleanly with full text stream');

  // 2.2 DOCX Extractor
  const docxFile = path.join(docsDir, 'Business_Continuity_Plan_2026.docx');
  const docxRes = await defaultRegistry.extract(docxFile);
  assert.ok(docxRes.text.includes('BUSINESS CONTINUITY PLAN'), 'DOCX extraction missing title');
  assert.ok(docxRes.text.includes('Recovery Time Objective'), 'DOCX extraction missing body text');
  console.log('  ✔ [DOCX] Real OOXML DOCX extracted with headings and body');

  // 2.3 XLSX Extractor
  const xlsxFile = path.join(docsDir, 'Refresher_Training_Attendance_2026.xlsx');
  const xlsxRes = await defaultRegistry.extract(xlsxFile);
  assert.ok(xlsxRes.text.includes('John Synthetic'), 'XLSX extraction missing participant');
  assert.ok(xlsxRes.text.includes('Sarah Jenkins'), 'XLSX extraction missing trainer');
  assert.ok(xlsxRes.tables && xlsxRes.tables.length > 0, 'XLSX extraction missing tables');
  console.log('  ✔ [XLSX] Real OOXML XLSX extracted with worksheets and tabular cells');

  // 2.4 PPTX Extractor
  const pptxFile = path.join(docsDir, 'Fire_Safety_Evacuation_Drill_Report_2026.pptx');
  const pptxRes = await defaultRegistry.extract(pptxFile);
  assert.ok(pptxRes.text.includes('FIRE SAFETY'), 'PPTX extraction missing slide title');
  assert.ok(pptxRes.text.includes('2026-06-01'), 'PPTX extraction missing drill date');
  console.log('  ✔ [PPTX] Real OOXML PPTX extracted with slide shapes and notes');

  // 2.5 CSV Extractor
  const csvFile = path.join(docsDir, 'Endpoint_Antivirus_EDR_Console_Export.csv');
  const csvRes = await defaultRegistry.extract(csvFile);
  assert.ok(csvRes.text.includes('Microsoft Defender'), 'CSV extraction missing antivirus text');
  assert.ok(csvRes.tables && csvRes.tables.length > 0, 'CSV extraction missing table data');
  console.log('  ✔ [CSV] CSV RFC-4180 extracted with row records');

  // 2.6 TXT Extractor
  const txtFile = path.join(docsDir, 'Escalation_Matrix_Hierarchy.txt');
  const txtRes = await defaultRegistry.extract(txtFile);
  assert.ok(txtRes.text.includes('LEVEL 1'), 'TXT extraction missing Level 1');
  assert.ok(txtRes.text.includes('LEVEL 4'), 'TXT extraction missing Level 4');
  console.log('  ✔ [TXT] UTF-8 Text extracted with line structures\n');

  // STEP 3: Execute Production Pipeline End-to-End Audit Scan
  console.log('[STEP 3] Executing Production Audit Scan via EvidenceEngine...');
  const db = getDatabase(':memory:');
  const engine = new EvidenceEngine(db);
  const auditDate = expectedResults.audit_date || '2026-08-14';

  const session = await engine.runAuditScan(
    generatedFiles,
    auditDate,
    expectedResults.agency_name,
    expectedResults.auditor_name
  );

  assert.ok(session, 'Audit session must be generated');
  assert.ok(session.parameter_results, 'Session must include parameter results');
  assert.strictEqual(session.parameter_results.length, INITIAL_AUDIT_CHECKLIST.length, 'All checklist parameters evaluated');
  console.log(`  ✔ Evaluated ${session.parameter_results.length} parameters over ${generatedFiles.length} production files.\n`);

  // STEP 4: Validate Parameter Compliance Outcomes Against Expectations
  console.log('[STEP 4] Validating Parameter-Level Outcomes...');
  const paramMap = new Map(session.parameter_results.map(r => [r.parameter_id, r]));

  // Verify Zero Tolerance (ZTI) controls
  // ZTI-001 (GST Certificate -> PASS)
  const zti001 = paramMap.get('ZTI-001')!;
  assert.strictEqual(zti001.status, 'PASS', 'ZTI-001 should PASS with valid GST certificate');
  assert.ok(zti001.score_earned > 0, 'ZTI-001 earned score');

  // ZTI-002 (Access Control -> PASS)
  const zti002 = paramMap.get('ZTI-002')!;
  assert.strictEqual(zti002.status, 'PASS', 'ZTI-002 should PASS with biometric log');

  // ZTI-003 (Dedicated Workspace -> PASS)
  const zti003 = paramMap.get('ZTI-003')!;
  assert.strictEqual(zti003.status, 'PASS', 'ZTI-003 should PASS with phone lending space');

  // ZTI-004 (DRA Certificate -> PASS)
  const zti004 = paramMap.get('ZTI-004')!;
  assert.strictEqual(zti004.status, 'PASS', 'ZTI-004 should PASS with valid DRA certificate');

  // ZTI-005 (Police Verification -> PASS)
  const zti005 = paramMap.get('ZTI-005')!;
  assert.strictEqual(zti005.status, 'PASS', 'ZTI-005 should PASS with verified PCC');
  assert.strictEqual(zti005.pv_status, 'VERIFIED', 'ZTI-005 pv_status should be VERIFIED');

  // ZTI-006 (Misconduct Breach -> EVIDENCE_NOT_FOUND)
  const zti006 = paramMap.get('ZTI-006')!;
  assert.strictEqual(zti006.status, 'EVIDENCE_NOT_FOUND', 'ZTI-006 should be EVIDENCE_NOT_FOUND when no log exists');

  // ZTI-007 (Agent Onboarding -> PASS)
  const zti007 = paramMap.get('ZTI-007')!;
  assert.strictEqual(zti007.status, 'PASS', 'ZTI-007 should PASS with KYC onboarding dossier');

  // ZTI-008 (USB Restriction AND Compound -> PASS)
  const zti008 = paramMap.get('ZTI-008')!;
  assert.strictEqual(zti008.status, 'PASS', 'ZTI-008 should PASS with both policy and GPO export');

  // ZTI-009 (Web Filtering AND Compound -> PASS)
  const zti009 = paramMap.get('ZTI-009')!;
  assert.strictEqual(zti009.status, 'PASS', 'ZTI-009 should PASS with policy and firewall rules export');

  // ZTI-010 (Clean Desk -> REVIEW)
  const zti010 = paramMap.get('ZTI-010')!;
  assert.strictEqual(zti010.status, 'REVIEW', 'ZTI-010 requires human auditor review');

  // Verify Governance, Compliance & INFOSEC (GCI) controls
  // GCI-001 (Agency ID & Field Endorsement -> PASS)
  const gci001 = paramMap.get('GCI-001')!;
  assert.strictEqual(gci001.status, 'PASS', 'GCI-001 should PASS with active ID cards');

  // GCI-002 (Termination SOP Policy Only -> REVIEW)
  const gci002 = paramMap.get('GCI-002')!;
  assert.strictEqual(gci002.status, 'REVIEW', 'GCI-002 should be REVIEW for policy-only document');
  assert.strictEqual(gci002.policy_status, 'POLICY_ONLY', 'GCI-002 policy_status should be POLICY_ONLY');

  // GCI-003 (Staff Attire -> EVIDENCE_NOT_FOUND)
  const gci003 = paramMap.get('GCI-003')!;
  assert.strictEqual(gci003.status, 'EVIDENCE_NOT_FOUND', 'GCI-003 should be EVIDENCE_NOT_FOUND');

  // GCI-004 (Refresher Training -> PASS)
  const gci004 = paramMap.get('GCI-004')!;
  assert.strictEqual(gci004.status, 'PASS', 'GCI-004 should PASS with training attendance workbook');

  // GCI-005 (Performance Evaluation -> PASS)
  const gci005 = paramMap.get('GCI-005')!;
  assert.strictEqual(gci005.status, 'PASS', 'GCI-005 should PASS with target vs actual workbook');

  // GCI-006 (Snipping Tool Policy Only -> REVIEW)
  const gci006 = paramMap.get('GCI-006')!;
  assert.strictEqual(gci006.status, 'REVIEW', 'GCI-006 should be REVIEW for policy document alone');

  // GCI-007 (Password Policy AD GPO -> PASS)
  const gci007 = paramMap.get('GCI-007')!;
  assert.strictEqual(gci007.status, 'PASS', 'GCI-007 should PASS with AD GPO export');

  // GCI-008 (Windows OS Update -> PASS)
  const gci008 = paramMap.get('GCI-008')!;
  assert.strictEqual(gci008.status, 'PASS', 'GCI-008 should PASS with patch compliance report');

  // Verify Infrastructure & Process Management (IPM) controls
  // IPM-001 (PF/ESIC OR Principal Employer -> PASS)
  const ipm001 = paramMap.get('IPM-001')!;
  assert.strictEqual(ipm001.status, 'PASS', 'IPM-001 should PASS via Principal Employer registration certificate');

  // IPM-002 (HR & POSH Policy -> PASS)
  const ipm002 = paramMap.get('IPM-002')!;
  assert.strictEqual(ipm002.status, 'PASS', 'IPM-002 should PASS with POSH policy');

  // IPM-003 (Rent Lease AND Shops Act -> PASS)
  const ipm003 = paramMap.get('IPM-003')!;
  assert.strictEqual(ipm003.status, 'PASS', 'IPM-003 should PASS with both Lease and Shops certificate');

  // IPM-004 (CGL Insurance Policy Expiry Check -> PASS)
  const ipm004 = paramMap.get('IPM-004')!;
  assert.strictEqual(ipm004.status, 'PASS', 'IPM-004 should PASS with active unexpired insurance policy');

  // IPM-005 (Visitor Register CSV -> PASS)
  const ipm005 = paramMap.get('IPM-005')!;
  assert.strictEqual(ipm005.status, 'PASS', 'IPM-005 should PASS with visitor entry log');

  // IPM-006 (CCTV AND 90 Days Retention -> PASS)
  const ipm006 = paramMap.get('IPM-006')!;
  assert.strictEqual(ipm006.status, 'PASS', 'IPM-006 should PASS with camera inventory and retention config');

  // IPM-007 (Fire Extinguisher GROUP -> PASS)
  const ipm007 = paramMap.get('IPM-007')!;
  assert.strictEqual(ipm007.status, 'PASS', 'IPM-007 should PASS with functional unexpired extinguisher inspection log');

  // IPM-008 (Fire Drill Recency Check -> PASS)
  const ipm008 = paramMap.get('IPM-008')!;
  assert.strictEqual(ipm008.status, 'PASS', 'IPM-008 should PASS with fire drill conducted on 2026-06-01 (<365 days)');

  // IPM-009 (Power, Internet, Antivirus GROUP -> PASS)
  const ipm009 = paramMap.get('IPM-009')!;
  assert.strictEqual(ipm009.status, 'PASS', 'IPM-009 should PASS with UPS, secondary ISP failover, and Antivirus EDR');

  // IPM-010 (BCP Plan -> PASS)
  const ipm010 = paramMap.get('IPM-010')!;
  assert.strictEqual(ipm010.status, 'PASS', 'IPM-010 should PASS with BCP policy');

  // IPM-011 (Escalation Matrix -> PASS)
  const ipm011 = paramMap.get('IPM-011')!;
  assert.strictEqual(ipm011.status, 'PASS', 'IPM-011 should PASS with escalation hierarchy');

  console.log('  ✔ All 29 parameters correctly evaluated across PASS, REVIEW, and EVIDENCE_NOT_FOUND.\n');

  // STEP 5: Verify Session-Level Entity Resolution & Conflict Detection
  console.log('[STEP 5] Verifying Session-Level Entity Resolution & Conflict Detection...');
  assert.ok(session.entities && session.entities.length >= 1, 'Should resolve primary entities');

  const johnEntity = session.entities.find(e => e.normalizedName.includes('john synthetic'));
  assert.ok(johnEntity, 'John Synthetic entity must be resolved');
  assert.strictEqual(johnEntity.identifiers.agentId, 'AG-GOLD-001', 'John Synthetic Agent ID mapped');
  assert.ok(johnEntity.evidenceReferences.length >= 3, 'John Synthetic linked to multiple cross-document evidence items');

  // Verify Conflict Case: Jane Synthetic associated with AG-GOLD-001
  assert.ok(session.entity_conflicts && session.entity_conflicts.length > 0, 'Entity conflict must be detected');
  const idConflict = session.entity_conflicts.find(c => c.conflictType === 'POSSIBLE_ENTITY_MISMATCH' || c.conflictType === 'AGENT_ID_NAME_MISMATCH');
  assert.ok(idConflict, 'Agent ID / Name mismatch conflict must be present for AG-GOLD-001');
  console.log(`  ✔ Successfully resolved entities and detected entity conflict: ${idConflict.title} (${idConflict.reason})`);

  // Overall session status must reflect NEEDS_REVIEW due to entity conflict and review items
  assert.strictEqual(session.overall_status, 'NEEDS_REVIEW', 'Overall status must be NEEDS_REVIEW');
  console.log('  ✔ Overall audit session correctly assigned status NEEDS_REVIEW.\n');

  // STEP 6: Direct Negative & Hardening Test Cases
  console.log('[STEP 6] Verifying Negative & Hardening Test Cases...');
  const matcher = new EvidenceMatcher();
  const evaluator = new AuditEvaluator();

  // Test Case 1: Filename Spoofing
  const gstParam = INITIAL_AUDIT_CHECKLIST.find(p => p.id === 'ZTI-001')!;
  const spoofedFile = path.join(docsDir, 'GST_Policy_Spoofed_Filename.pdf');
  const spoofedExtraction = await defaultRegistry.extract(spoofedFile);
  const spoofedEvidence = matcher.evaluateEvidence('f-sp', 'GST_Policy_Spoofed_Filename.pdf', spoofedFile, gstParam, spoofedExtraction);
  assert.ok(spoofedEvidence !== null, 'Candidate matched based on filename');
  assert.strictEqual(spoofedEvidence.validated, false, 'Spoofed file must NOT pass structured validation');
  const spoofResult = evaluator.evaluateParameter(gstParam, [spoofedEvidence], auditDate);
  assert.strictEqual(spoofResult.status, 'REVIEW', 'Spoofed candidate must yield REVIEW');
  console.log('  ✔ Case 1: Filename spoofing candidate correctly prevented from passing.');

  // Test Case 2: Generic Keyword Match
  const genericKwFile = path.join(docsDir, 'Generic_PF_ESIC_Policy_Keyword_Only.txt');
  const genericKwExtraction = await defaultRegistry.extract(genericKwFile);
  const ipm001Param = INITIAL_AUDIT_CHECKLIST.find(p => p.id === 'IPM-001')!;
  const genericEvidence = matcher.evaluateEvidence('f-gen', 'Generic_PF_ESIC_Policy_Keyword_Only.txt', genericKwFile, ipm001Param, genericKwExtraction);
  assert.ok(genericEvidence !== null, 'Candidate matched');
  assert.strictEqual(genericEvidence.validated, false, 'Generic statement must fail structured validation');
  console.log('  ✔ Case 2: Generic keyword match fails domain field validation.');

  // Test Case 3: Expired Document Evaluation
  const expiredFile = path.join(docsDir, 'Expired_Insurance_Policy_Sample.pdf');
  const expiredExtraction = await defaultRegistry.extract(expiredFile);
  const ipm004Param = INITIAL_AUDIT_CHECKLIST.find(p => p.id === 'IPM-004')!;
  const expiredEvidence = matcher.evaluateEvidence('f-exp', 'Expired_Insurance_Policy_Sample.pdf', expiredFile, ipm004Param, expiredExtraction);
  assert.ok(expiredEvidence !== null, 'Candidate matched');
  assert.strictEqual(expiredEvidence.extracted_fields?.expiry_date, '2026-03-31', 'Extracted expiry date 2026-03-31');
  const expiredResult = evaluator.evaluateParameter(ipm004Param, [expiredEvidence], auditDate);
  assert.strictEqual(expiredResult.status, 'FAIL', 'Expired insurance policy must FAIL when evaluated against audit date 2026-08-14');
  console.log('  ✔ Case 3: Expired document correctly yields FAIL status against audit date.');

  // Test Case 4: DateEvaluator safety checks
  assert.strictEqual(DateEvaluator.isExpired('2026-03-31', '2026-08-14'), true, '2026-03-31 is expired relative to 2026-08-14');
  assert.strictEqual(DateEvaluator.isExpired('2027-03-31', '2026-08-14'), false, '2027-03-31 is NOT expired relative to 2026-08-14');
  assert.strictEqual(DateEvaluator.isOlderThanDays('2026-06-01', '2026-08-14', 365), false, '2026-06-01 is within 365 days of 2026-08-14');
  assert.strictEqual(DateEvaluator.isOlderThanDays('2025-01-01', '2026-08-14', 365), true, '2025-01-01 is older than 365 days of 2026-08-14');
  console.log('  ✔ Case 4: DateEvaluator recency and expiration functions verified.\n');

  console.log('================================================================');
  console.log('  ✔ Golden Audit Dataset & Production Pipeline 100% Verified!   ');
  console.log('================================================================\n');
}

runGoldenAuditTestSuite().then(() => {
  process.exit(0);
}).catch(err => {
  console.error('Golden Audit Test Suite Failed:', err);
  process.exit(1);
});
