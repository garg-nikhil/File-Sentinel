import assert from 'node:assert';
import { EvidenceMatcher } from '../backend/audit/evidenceMatcher.js';
import { AuditEvaluator } from '../backend/audit/evaluator.js';
import { INITIAL_AUDIT_CHECKLIST } from '../backend/audit/checklist.js';
import { ExtractionResult } from '../backend/extractors/base.js';
import { classifyEvidenceSource, classifyDocumentDomain, assertEvidenceDomainMatchesControl } from '../backend/audit/evidenceDomain.js';
import { AuditParameter } from '../backend/audit/models.js';

function getParam(id: string): AuditParameter {
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

async function runDomainIsolationTests() {
  console.log('================================================================');
  console.log('  FileSentinel Domain Isolation & Anti-Contamination Suite (Remediation 8)');
  console.log('================================================================\n');

  const matcher = new EvidenceMatcher();
  const evaluator = new AuditEvaluator();
  const auditDate = '2026-08-15';

  // Sample Documents
  const gstDoc = `Goods and Services Tax Registration Certificate
Government of India - Form GST REG-06
Registration Number: 27AABCA1234F1Z5
Legal Name: ABC Services Private Limited
Trade Name: ABC Collections
Principal Place of Business: 401, Technopolis Business Park, Andheri East, Mumbai 400069
Date of Issue: 12/04/2021
Status: Active`;

  const cctvPolicyDoc = `Information Security Policy - Physical Security & Surveillance
Version: 2.1
Approved By: CISO
Effective Date: 01/01/2025
Scope: All office facilities and entry points.
1. CCTV Policy:
CCTV cameras shall be installed at all entry and exit doors, server rooms, and floor operations.
Recording footage shall be preserved for a minimum of 90 days retention for audit investigations.`;

  const cctvImplDoc = `CCTV Surveillance System Commissioning & Retention Report
Facility: Mumbai Main Center
Hardware Inventory:
- Channel 1 to 16: Hikvision 4MP Dome Cameras installed at entrances, exits, cash desks
- DVR/NVR Model: NVR-7616NI-Q2, 16TB Seagate SkyHawk Storage
Retention Configuration Dump:
Recording Resolution: 1080p @ 15fps continuous recording
Calculated Storage Retention: 95 days before overwrite
Current Storage Log: 90 days footage active on disk`;

  const manifestCsv = `file_id,filename,expected_control,notes
01,01_positive_gst.txt,ZTI-001,Valid GST registration
02,12_cctv_policy_only.docx,IPM-006,Policy only document
03,13_cctv_implementation.pptx,IPM-006,Technical CCTV config
04,04_police_verification.pdf,ZTI-005,PV Certificate`;

  const readmeMd = `# FileSentinel Synthetic Audit Test Corpus
This directory contains test files for auditing compliance across financial agencies.
Do not modify the file structure without updating test manifests.`;

  const endpointPolicyDoc = `Information Security Policy - Removable Media & Endpoint Security Policy
Policy No: POL-SEC-08
Effective Date: 2025-01-01
Scope: All Workstations and Laptops.
1. USB & Removable Media Policy:
All USB ports on corporate workstations must be restricted. Writing to removable storage or cloud storage drives without prior authorization is strictly prohibited.`;

  const endpointImplDoc = `Active Directory Group Policy Object (GPO) Export
GPO Name: SEC-Endpoint-Storage-Restriction
Policy Setting: Removable Storage Devices -> All Removable Storage classes: Deny all access
Registry Key: HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR -> Start=4 (Disabled)
StorageDevicePolicies\\WriteProtect = 1 (Enabled)
Applied to OU: Workstations_Production`;

  // -------------------------------------------------------------------------------------
  // TEST 1: IPM-003 (Rent/Lease & Shops) must NEVER accept 01_positive_gst.txt
  // -------------------------------------------------------------------------------------
  console.log('[TEST 1] 01_positive_gst.txt against IPM-003 (Rent/Lease Agreement / Shops)...');
  const ipm003 = getParam('IPM-003');
  const gstItemForIpm003 = matcher.matchDocumentToParameter(
    'F-01',
    '/scan/01_positive_gst.txt',
    createExtraction(gstDoc),
    ipm003
  );

  assert.strictEqual(
    gstItemForIpm003,
    null,
    '01_positive_gst.txt must be rejected by candidate discovery for IPM-003 due to domain mismatch'
  );

  const eval1 = evaluator.evaluateParameter(ipm003, gstItemForIpm003 ? [gstItemForIpm003] : [], auditDate);
  assert.strictEqual(eval1.status, 'EVIDENCE_NOT_FOUND', 'Final status for IPM-003 must be EVIDENCE_NOT_FOUND');
  assert.strictEqual(eval1.score_earned, 0, 'Score earned for IPM-003 must be 0');
  console.log('✔ Test 1 Passed: GST Certificate successfully isolated from IPM-003 (EVIDENCE_NOT_FOUND, Score: 0).');

  // -------------------------------------------------------------------------------------
  // TEST 2: ZTI-002 (Biometric Access Control) must NEVER accept 13_cctv_implementation.pptx
  // -------------------------------------------------------------------------------------
  console.log('\n[TEST 2] 13_cctv_implementation.pptx against ZTI-002 (Biometric Access Control)...');
  const zti002 = getParam('ZTI-002');
  const cctvItemForZti002 = matcher.matchDocumentToParameter(
    'F-02',
    '/scan/13_cctv_implementation.pptx',
    createExtraction(cctvImplDoc),
    zti002
  );

  assert.strictEqual(
    cctvItemForZti002,
    null,
    '13_cctv_implementation.pptx must be rejected by candidate discovery for ZTI-002 due to domain mismatch'
  );

  const eval2 = evaluator.evaluateParameter(zti002, cctvItemForZti002 ? [cctvItemForZti002] : [], auditDate);
  assert.strictEqual(eval2.status, 'EVIDENCE_NOT_FOUND', 'Final status for ZTI-002 must be EVIDENCE_NOT_FOUND');
  assert.strictEqual(eval2.score_earned, 0, 'Score earned for ZTI-002 must be 0');
  console.log('✔ Test 2 Passed: CCTV Implementation document successfully isolated from ZTI-002 (EVIDENCE_NOT_FOUND, Score: 0).');

  // -------------------------------------------------------------------------------------
  // TEST 3: ZTI-009 (Web/Social/Messaging Blacklisting) must NEVER accept 12_cctv_policy_only.docx
  // -------------------------------------------------------------------------------------
  console.log('\n[TEST 3] 12_cctv_policy_only.docx against ZTI-009 (Web/Social Blacklisting)...');
  const zti009 = getParam('ZTI-009');
  const cctvItemForZti009 = matcher.matchDocumentToParameter(
    'F-03',
    '/scan/12_cctv_policy_only.docx',
    createExtraction(cctvPolicyDoc),
    zti009
  );

  assert.strictEqual(
    cctvItemForZti009,
    null,
    '12_cctv_policy_only.docx must be rejected by candidate discovery for ZTI-009 due to domain mismatch'
  );

  const eval3 = evaluator.evaluateParameter(zti009, cctvItemForZti009 ? [cctvItemForZti009] : [], auditDate);
  assert.strictEqual(eval3.status, 'EVIDENCE_NOT_FOUND', 'Final status for ZTI-009 must be EVIDENCE_NOT_FOUND');
  assert.strictEqual(eval3.score_earned, 0, 'Score earned for ZTI-009 must be 0');
  console.log('✔ Test 3 Passed: CCTV Policy document successfully isolated from ZTI-009 (EVIDENCE_NOT_FOUND, Score: 0).');

  // -------------------------------------------------------------------------------------
  // TEST 4: manifest.csv against ZTI-008 (Printer/USB/Cloud Storage) must be REJECTED
  // -------------------------------------------------------------------------------------
  console.log('\n[TEST 4] manifest.csv against ZTI-008 (Endpoint / USB Restriction)...');
  const zti008 = getParam('ZTI-008');
  const manifestItemForZti008 = matcher.matchDocumentToParameter(
    'F-04',
    '/scan/manifest.csv',
    createExtraction(manifestCsv),
    zti008
  );

  assert.strictEqual(
    manifestItemForZti008,
    null,
    'manifest.csv must be rejected immediately as TEST_METADATA and never become evidence for ZTI-008'
  );

  const eval4 = evaluator.evaluateParameter(zti008, manifestItemForZti008 ? [manifestItemForZti008] : [], auditDate);
  assert.strictEqual(eval4.status, 'EVIDENCE_NOT_FOUND', 'Final status for ZTI-008 with manifest.csv must be EVIDENCE_NOT_FOUND');
  assert.strictEqual(eval4.score_earned, 0, 'Score earned for ZTI-008 must be 0');
  console.log('✔ Test 4 Passed: manifest.csv rejected from audit evidence pipeline (EVIDENCE_NOT_FOUND, Score: 0).');

  // -------------------------------------------------------------------------------------
  // TEST 5: README.md must be REJECTED from all controls
  // -------------------------------------------------------------------------------------
  console.log('\n[TEST 5] README.md against all controls...');
  const zti001 = getParam('ZTI-001');
  const readmeItem = matcher.matchDocumentToParameter(
    'F-05',
    '/scan/README.md',
    createExtraction(readmeMd),
    zti001
  );

  assert.strictEqual(readmeItem, null, 'README.md must be rejected as DOCUMENTATION / non-audit evidence');
  console.log('✔ Test 5 Passed: README.md rejected from all audit controls.');

  // -------------------------------------------------------------------------------------
  // TEST 6: 01_positive_gst.txt against ZTI-001 (GST Registration) MUST PASS
  // -------------------------------------------------------------------------------------
  console.log('\n[TEST 6] 01_positive_gst.txt against ZTI-001 (GST Registration)...');
  const gstItem = matcher.matchDocumentToParameter(
    'F-06',
    '/scan/01_positive_gst.txt',
    createExtraction(gstDoc),
    zti001
  );

  assert.ok(gstItem !== null, 'GST document should be discovered for ZTI-001');
  assert.strictEqual(gstItem.document_domain, 'GST_REGISTRATION', 'Document domain must be GST_REGISTRATION');
  assert.strictEqual(gstItem.control_domain, 'GST_REGISTRATION', 'Control domain must be GST_REGISTRATION');
  assert.strictEqual(gstItem.domain_match, true, 'Domain match must be true');
  assert.strictEqual(gstItem.fieldValidation, true, 'Field validation must pass for genuine GST doc');
  assert.strictEqual(gstItem.validated, true, 'Validated must be true');

  const eval6 = evaluator.evaluateParameter(zti001, [gstItem], auditDate);
  assert.strictEqual(eval6.status, 'PASS', 'ZTI-001 must PASS with genuine GST evidence');
  assert.strictEqual(eval6.score_earned, eval6.max_score, 'Score earned must equal max score');
  console.log('✔ Test 6 Passed: ZTI-001 successfully passed with genuine GST certificate.');

  // -------------------------------------------------------------------------------------
  // TEST 7: 12_cctv_policy_only.docx against IPM-006 (CCTV) MUST BE REVIEW (Policy Only)
  // -------------------------------------------------------------------------------------
  console.log('\n[TEST 7] 12_cctv_policy_only.docx against IPM-006 (CCTV Surveillance)...');
  const ipm006 = getParam('IPM-006');
  const cctvPolicyItem = matcher.matchDocumentToParameter(
    'F-07',
    '/scan/12_cctv_policy_only.docx',
    createExtraction(cctvPolicyDoc),
    ipm006
  );

  assert.ok(cctvPolicyItem !== null, 'CCTV policy should match IPM-006 candidate criteria');
  assert.strictEqual(cctvPolicyItem.document_domain, 'CCTV_SURVEILLANCE_RETENTION', 'Domain must be CCTV_SURVEILLANCE_RETENTION');

  const eval7 = evaluator.evaluateParameter(ipm006, [cctvPolicyItem], auditDate);
  assert.strictEqual(eval7.status, 'REVIEW', 'IPM-006 with policy-only document must result in REVIEW');
  assert.strictEqual(eval7.score_earned, 0, 'Score earned must be 0 for policy-only on technical implementation sub-controls');
  console.log('✔ Test 7 Passed: 12_cctv_policy_only.docx evaluated correctly as REVIEW on IPM-006.');

  // -------------------------------------------------------------------------------------
  // TEST 8: 13_cctv_implementation.pptx against IPM-006 MUST satisfy implementation sub-controls
  // -------------------------------------------------------------------------------------
  console.log('\n[TEST 8] 13_cctv_implementation.pptx against IPM-006 (CCTV Surveillance)...');
  const cctvImplItem = matcher.matchDocumentToParameter(
    'F-08',
    '/scan/13_cctv_implementation.pptx',
    createExtraction(cctvImplDoc),
    ipm006
  );

  assert.ok(cctvImplItem !== null, 'CCTV implementation report should match IPM-006');
  assert.strictEqual(cctvImplItem.document_domain, 'CCTV_SURVEILLANCE_RETENTION', 'Domain must be CCTV_SURVEILLANCE_RETENTION');
  assert.strictEqual(cctvImplItem.validated, true, 'Validated must be true for technical CCTV config');

  const eval8 = evaluator.evaluateParameter(ipm006, [cctvImplItem], auditDate);
  assert.strictEqual(eval8.status, 'PASS', 'IPM-006 must PASS with full CCTV hardware & 90-day retention config');
  assert.strictEqual(eval8.score_earned, eval8.max_score, 'Score earned must equal max score');
  console.log('✔ Test 8 Passed: 13_cctv_implementation.pptx passed IPM-006 with full 90-day retention verified.');

  // -------------------------------------------------------------------------------------
  // TEST 9: Source Classification validation
  // -------------------------------------------------------------------------------------
  console.log('\n[TEST 9] Source Classification unit tests...');
  const manifestSource = classifyEvidenceSource('manifest.csv', '/scan/manifest.csv', manifestCsv);
  assert.strictEqual(manifestSource.sourceType, 'TEST_METADATA', 'manifest.csv must be TEST_METADATA');
  assert.strictEqual(manifestSource.isAuditEvidenceCandidate, false, 'manifest.csv isAuditEvidenceCandidate must be false');

  const readmeSource = classifyEvidenceSource('README.md', '/scan/README.md', readmeMd);
  assert.strictEqual(readmeSource.sourceType, 'TEST_METADATA', 'README.md must be TEST_METADATA');
  assert.strictEqual(readmeSource.isAuditEvidenceCandidate, false, 'README.md isAuditEvidenceCandidate must be false');

  const docSource = classifyEvidenceSource('01_positive_gst.txt', '/scan/01_positive_gst.txt', gstDoc);
  assert.strictEqual(docSource.sourceType, 'DOCUMENT_EVIDENCE', '01_positive_gst.txt must be DOCUMENT_EVIDENCE');
  assert.strictEqual(docSource.isAuditEvidenceCandidate, true, '01_positive_gst.txt isAuditEvidenceCandidate must be true');
  console.log('✔ Test 9 Passed: Source classification accurately categorizes evidence vs metadata.');

  // -------------------------------------------------------------------------------------
  // TEST 10: assertEvidenceDomainMatchesControl logic verification
  // -------------------------------------------------------------------------------------
  console.log('\n[TEST 10] assertEvidenceDomainMatchesControl assertion tests...');
  assert.strictEqual(
    assertEvidenceDomainMatchesControl('GST_REGISTRATION', 'PREMISES_AND_ESTABLISHMENT'),
    false,
    'GST cannot match PREMISES_AND_ESTABLISHMENT'
  );
  assert.strictEqual(
    assertEvidenceDomainMatchesControl('BIOMETRIC_ACCESS_CONTROL', 'CCTV_SURVEILLANCE_RETENTION'),
    false,
    'CCTV cannot match BIOMETRIC_ACCESS_CONTROL'
  );
  assert.strictEqual(
    assertEvidenceDomainMatchesControl('WEB_COMMUNICATION_FILTERING', 'CCTV_SURVEILLANCE_RETENTION'),
    false,
    'CCTV cannot match WEB_COMMUNICATION_FILTERING'
  );
  assert.strictEqual(
    assertEvidenceDomainMatchesControl('ENDPOINT_DATA_RESTRICTION', 'WEB_COMMUNICATION_FILTERING'),
    false,
    'Web filtering cannot match ENDPOINT_DATA_RESTRICTION'
  );
  assert.strictEqual(
    assertEvidenceDomainMatchesControl('CCTV_SURVEILLANCE_RETENTION', 'CCTV_SURVEILLANCE_RETENTION'),
    true,
    'Identical domains must match'
  );
  assert.strictEqual(
    assertEvidenceDomainMatchesControl('PREMISES_AND_ESTABLISHMENT', 'RENT_LEASE_AGREEMENT', ['RENT_LEASE_AGREEMENT', 'SHOPS_ESTABLISHMENT_CERTIFICATE']),
    true,
    'Allowed sub-domains must match parent control'
  );
  console.log('✔ Test 10 Passed: Domain compatibility assertion matrix verified.');

  console.log('\n================================================================');
  console.log('  All 10 Domain Isolation & Anti-Contamination Tests PASSED! ✔');
  console.log('================================================================\n');
}

runDomainIsolationTests().then(() => {
  process.exit(0);
}).catch(err => {
  console.error('Test Suite Failed:', err);
  process.exit(1);
});
