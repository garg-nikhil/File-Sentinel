import assert from 'node:assert';
import { EvidenceMatcher } from '../backend/audit/evidenceMatcher.js';
import { AuditEvaluator } from '../backend/audit/evaluator.js';
import { INITIAL_AUDIT_CHECKLIST } from '../backend/audit/checklist.js';
import { ExtractionResult } from '../backend/extractors/base.js';

function getParam(id: string) {
  const param = INITIAL_AUDIT_CHECKLIST.find(p => p.id === id);
  assert.ok(param, `Parameter ${id} must exist in checklist`);
  return param;
}

function createExtraction(text: string, warnings: string[] = []): ExtractionResult {
  return {
    text,
    metadata: {},
    links: [],
    embeddedObjects: [],
    structure: {},
    warnings
  };
}

async function runEvidenceHardeningTests() {
  console.log('====================================================');
  console.log('  FileSentinel Evidence Hardening Test Suite (Remediation 1)');
  console.log('====================================================\n');

  const matcher = new EvidenceMatcher();
  const evaluator = new AuditEvaluator();
  const auditDate = '2026-08-13';

  // ----------------------------------------------------
  // TEST 1: Correct filename + unrelated content (Spoofing)
  // ----------------------------------------------------
  console.log('[TEST 1] Correct filename + unrelated content (ZTI-001)...');
  const zti001 = getParam('ZTI-001');
  const item1 = matcher.matchDocumentToParameter(
    'FILE-01',
    '/workspace/GST_Registration_Certificate.pdf',
    createExtraction('This is a completely unrelated brochure discussing office interior decoration and furniture.'),
    zti001
  );

  assert.ok(item1 !== null, 'Candidate item should be discovered based on filename');
  assert.strictEqual(item1.filenameMatch, true, 'filenameMatch must be true');
  assert.strictEqual(item1.contentMatch, false, 'contentMatch must be false');
  assert.strictEqual(item1.isFilenameOnly, true, 'isFilenameOnly must be true');
  assert.strictEqual(item1.fieldValidation, false, 'fieldValidation must be false');
  assert.strictEqual(item1.validated, false, 'validated must be false');
  assert.strictEqual(item1.satisfiesControl, false, 'satisfiesControl must be false');

  const eval1 = evaluator.evaluateParameter(zti001, [item1], auditDate);
  assert.strictEqual(eval1.status, 'REVIEW', 'Final audit status must be REVIEW (never PASS)');
  assert.strictEqual(eval1.score_earned, 0, 'Score earned must be 0');
  console.log('✔ Test 1 Passed: Unrelated content with valid filename correctly evaluated as REVIEW (Score: 0).');

  // ----------------------------------------------------
  // TEST 2: Correct filename + generic keyword only (The prompt core requirement)
  // ----------------------------------------------------
  console.log('\n[TEST 2] Correct filename + generic keyword only (ZTI-001)...');
  const item2 = matcher.matchDocumentToParameter(
    'FILE-02',
    '/workspace/GST_Registration_Certificate.pdf',
    createExtraction('This is an internal policy describing GST compliance requirements.'),
    zti001
  );

  assert.ok(item2 !== null, 'Candidate item should be created');
  assert.strictEqual(item2.filenameMatch, true, 'filenameMatch must be true');
  assert.strictEqual(item2.contentMatch, true, 'contentMatch must be true');
  assert.strictEqual(item2.fieldValidation, false, 'fieldValidation must be false because no GSTIN or structured cert fields exist');
  assert.strictEqual(item2.validated, false, 'validated must be false');
  assert.strictEqual(item2.satisfiesControl, false, 'satisfiesControl must be false');

  const eval2 = evaluator.evaluateParameter(zti001, [item2], auditDate);
  assert.strictEqual(eval2.status, 'REVIEW', 'Final audit status must be REVIEW (never PASS)');
  assert.strictEqual(eval2.score_earned, 0, 'Score earned must be 0');
  assert.ok(eval2.reason.includes('failed mandatory evidence validation') || eval2.reason.includes('cannot satisfy'), 'Reason must explain validation failure');
  console.log('✔ Test 2 Passed: Generic keyword match with filename correctly rejected from passing (Status: REVIEW, Score: 0).');

  // ----------------------------------------------------
  // TEST 3: Wrong filename + genuine evidence content
  // ----------------------------------------------------
  console.log('\n[TEST 3] Wrong filename + genuine evidence content (ZTI-001)...');
  const item3 = matcher.matchDocumentToParameter(
    'FILE-03',
    '/workspace/random_scan_notes_492.txt',
    createExtraction(`Goods and Services Tax Registration Certificate
Legal Name: ABC Collections Private Limited
GSTIN: 27XXXXXXXXXXXXXX
Registration status: Active`),
    zti001
  );

  assert.ok(item3 !== null, 'Item should match based on content');
  assert.strictEqual(item3.filenameMatch, false, 'filenameMatch must be false');
  assert.strictEqual(item3.contentMatch, true, 'contentMatch must be true');
  assert.strictEqual(item3.fieldValidation, true, 'fieldValidation must be true for valid GST registration content');
  assert.strictEqual(item3.validated, true, 'validated must be true');
  assert.strictEqual(item3.satisfiesControl, true, 'satisfiesControl must be true');

  const eval3 = evaluator.evaluateParameter(zti001, [item3], auditDate);
  assert.strictEqual(eval3.status, 'PASS', 'Final audit status must be PASS for genuine content');
  assert.strictEqual(eval3.score_earned, 10, 'Full score must be earned');
  console.log('✔ Test 3 Passed: Genuine content with arbitrary filename evaluated as PASS (Score: 10).');

  // ----------------------------------------------------
  // TEST 4: Generic policy mentioning the required term
  // ----------------------------------------------------
  console.log('\n[TEST 4] Generic policy mentioning required term without structure (ZTI-001)...');
  const item4 = matcher.matchDocumentToParameter(
    'FILE-04',
    '/workspace/Company_Handbook_v1.pdf',
    createExtraction('The company strictly follows all statutory GST and tax compliance policies.'),
    zti001
  );

  assert.ok(item4 !== null, 'Candidate discovered based on content keyword');
  assert.strictEqual(item4.fieldValidation, false, 'fieldValidation must be false');
  assert.strictEqual(item4.validated, false, 'validated must be false');
  assert.strictEqual(item4.satisfiesControl, false, 'satisfiesControl must be false');

  const eval4 = evaluator.evaluateParameter(zti001, [item4], auditDate);
  assert.strictEqual(eval4.status, 'REVIEW', 'Final audit status must be REVIEW (never PASS)');
  console.log('✔ Test 4 Passed: Generic policy text mentioning GST cannot satisfy ZTI-001.');

  // ----------------------------------------------------
  // TEST 5: Empty document
  // ----------------------------------------------------
  console.log('\n[TEST 5] Empty document handling...');
  const item5 = matcher.matchDocumentToParameter(
    'FILE-05',
    '/workspace/GST_Registration_Certificate.pdf',
    createExtraction(''),
    zti001
  );

  assert.ok(item5 !== null, 'Candidate discovered on filename');
  assert.strictEqual(item5.isFilenameOnly, true, 'isFilenameOnly must be true');
  assert.strictEqual(item5.validated, false, 'validated must be false');
  const eval5 = evaluator.evaluateParameter(zti001, [item5], auditDate);
  assert.strictEqual(eval5.status, 'REVIEW', 'Empty document cannot pass');
  console.log('✔ Test 5 Passed: Empty document correctly rejected.');

  // ----------------------------------------------------
  // TEST 6: Corrupt document (with extraction error warning)
  // ----------------------------------------------------
  console.log('\n[TEST 6] Corrupt document extraction handling...');
  const item6 = matcher.matchDocumentToParameter(
    'FILE-06',
    '/workspace/GST_Registration_Certificate.pdf',
    createExtraction('', ['Extraction failed due to corrupted file header']),
    zti001
  );

  assert.ok(item6 !== null);
  assert.strictEqual(item6.validated, false, 'Corrupted document is not validated');
  const eval6 = evaluator.evaluateParameter(zti001, [item6], auditDate);
  assert.strictEqual(eval6.status, 'REVIEW', 'Corrupt document cannot pass');
  console.log('✔ Test 6 Passed: Corrupted file cannot pass.');

  // ----------------------------------------------------
  // TEST 7: Genuine document with missing mandatory field (IPM-004 Insurance)
  // ----------------------------------------------------
  console.log('\n[TEST 7] Genuine document with missing mandatory field (IPM-004 Insurance)...');
  const ipm004 = getParam('IPM-004');
  const item7 = matcher.matchDocumentToParameter(
    'FILE-07',
    '/workspace/Insurance_Discussion_Notes.txt',
    createExtraction('This is a memo regarding our Commercial General Liability insurance policy requirement.'),
    ipm004
  );

  assert.ok(item7 !== null, 'Candidate discovered on keyword');
  assert.strictEqual(item7.fieldValidation, false, 'fieldValidation must be false due to missing policy number and coverage');
  assert.strictEqual(item7.validated, false, 'validated must be false');
  assert.strictEqual(item7.satisfiesControl, false, 'satisfiesControl must be false');

  const eval7 = evaluator.evaluateParameter(ipm004, [item7], auditDate);
  assert.strictEqual(eval7.status, 'REVIEW', 'Missing mandatory fields cannot pass');
  console.log('✔ Test 7 Passed: Insurance document missing policy number & coverage fails validation (Status: REVIEW).');

  // ----------------------------------------------------
  // TEST 8: Genuine document with valid mandatory field (IPM-004 Insurance)
  // ----------------------------------------------------
  console.log('\n[TEST 8] Genuine document with valid mandatory field (IPM-004 Insurance)...');
  const item8 = matcher.matchDocumentToParameter(
    'FILE-08',
    '/workspace/Commercial_General_Liability_Policy.txt',
    createExtraction(`COMMERCIAL GENERAL LIABILITY INSURANCE POLICY
Insurer: National Insurance Corp
Policy Number: CGL-2026-559012
Insured Organization: Zenith Telecalling & Collection Services
Coverage Amount: $1,000,000 USD
Start Date: 2026-01-01
Expiry Date: 2027-12-31
Status: ACTIVE`),
    ipm004
  );

  assert.ok(item8 !== null);
  assert.strictEqual(item8.fieldValidation, true, 'fieldValidation must be true');
  assert.strictEqual(item8.validated, true, 'validated must be true');
  assert.strictEqual(item8.satisfiesControl, true, 'satisfiesControl must be true');

  const eval8 = evaluator.evaluateParameter(ipm004, [item8], auditDate);
  assert.strictEqual(eval8.status, 'PASS', 'Valid insurance policy with active expiry date must PASS');
  console.log('✔ Test 8 Passed: Genuine insurance policy with structured policy number passes validation (Status: PASS).');

  // ----------------------------------------------------
  // TEST 9: DRA Certificate Validation (ZTI-004)
  // ----------------------------------------------------
  console.log('\n[TEST 9] DRA Certificate false-pass vs genuine validation (ZTI-004)...');
  const zti004 = getParam('ZTI-004');
  
  // Generic mention
  const itemDraFake = matcher.matchDocumentToParameter(
    'FILE-09A',
    '/workspace/DRA_Training_Notes.txt',
    createExtraction('Our agency trains agents according to DRA guidelines.'),
    zti004
  );
  assert.ok(itemDraFake !== null);
  assert.strictEqual(itemDraFake.validated, false, 'Generic DRA mention must not be validated');
  const evalDraFake = evaluator.evaluateParameter(zti004, [itemDraFake], auditDate);
  assert.strictEqual(evalDraFake.status, 'REVIEW', 'Generic DRA mention must be REVIEW');

  // Genuine certificate
  const itemDraReal = matcher.matchDocumentToParameter(
    'FILE-09B',
    '/workspace/DRA_Cert_John.txt',
    createExtraction(`NATIONAL BANKING & FINANCIAL EDUCATION TRUST
CERTIFICATE OF COMPLETION - DRA TRAINED
Agent / Employee: John Smith
Training Name: Debt Recovery Agent (DRA) Certification
Certificate Number: DRA-2026-99481
Status: PASSED
Issue Date: 2026-06-12
Expiry Date: 2029-06-12`),
    zti004
  );
  assert.ok(itemDraReal !== null);
  assert.strictEqual(itemDraReal.validated, true, 'Genuine DRA certificate must be validated');
  const evalDraReal = evaluator.evaluateParameter(zti004, [itemDraReal], auditDate);
  assert.strictEqual(evalDraReal.status, 'PASS', 'Genuine DRA certificate must PASS');
  console.log('✔ Test 9 Passed: DRA Certificate validation distinguishes generic text from genuine certificates.');

  // ----------------------------------------------------
  // TEST 10: Police Verification Validation (ZTI-005)
  // ----------------------------------------------------
  console.log('\n[TEST 10] Police Verification false-pass vs genuine validation (ZTI-005)...');
  const zti005 = getParam('ZTI-005');

  // Generic mention
  const itemPvFake = matcher.matchDocumentToParameter(
    'FILE-10A',
    '/workspace/PV_Discussion.txt',
    createExtraction('We submitted some police verification files yesterday.'),
    zti005
  );
  assert.ok(itemPvFake !== null);
  assert.strictEqual(itemPvFake.validated, false, 'Generic PV mention must not be validated');
  const evalPvFake = evaluator.evaluateParameter(zti005, [itemPvFake], auditDate);
  assert.strictEqual(evalPvFake.status, 'REVIEW', 'Generic PV mention must be REVIEW');

  // Genuine PV application
  const itemPvReal = matcher.matchDocumentToParameter(
    'FILE-10B',
    '/workspace/PV_Ack_John.txt',
    createExtraction(`STATE POLICE DEPARTMENT - CHARACTER & BACKGROUND CLEARANCE
Application Type: Police Verification Report (PV)
Employee: John Smith
Status: APPLIED
Acknowledgement Slip Number: PV-ACK-2026-8812
Date of Application: 10/07/2026
Expiry Date: 2027-07-10`),
    zti005
  );
  assert.ok(itemPvReal !== null);
  assert.strictEqual(itemPvReal.validated, true, 'Genuine PV acknowledgement must be validated');
  const evalPvReal = evaluator.evaluateParameter(zti005, [itemPvReal], auditDate);
  assert.strictEqual(evalPvReal.status, 'PASS', 'Genuine PV acknowledgement must PASS');
  console.log('✔ Test 10 Passed: Police verification validation distinguishes generic mention from valid application.');

  console.log('\n====================================================');
  console.log('   ALL 10 EVIDENCE HARDENING TESTS PASSED (100%)');
  console.log('====================================================\n');
}

runEvidenceHardeningTests().then(() => {
  process.exit(0);
}).catch(err => {
  console.error('\n❌ Evidence Hardening Test Suite Failed:', err);
  process.exit(1);
});
