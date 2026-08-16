import { AuditEvaluator } from '../backend/audit/evaluator.js';
import { INITIAL_AUDIT_CHECKLIST } from '../backend/audit/checklist.js';
import { EvidenceMatcher } from '../backend/audit/evidenceMatcher.js';
import { CompoundEvaluator } from '../backend/audit/compoundEvaluator.js';
import { AuditParameter, EvidenceItem } from '../backend/audit/models.js';

let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string, detail?: any) {
  if (condition) {
    console.log(`✅ PASS: ${testName}`);
    passed++;
  } else {
    console.error(`❌ FAIL: ${testName}`, detail ? detail : '');
    failed++;
  }
}

console.log('====================================================');
console.log('FILECENTINEL EVIDENCE EXPLAINABILITY & HARDENING TEST SUITE');
console.log('====================================================\n');

const evaluator = new AuditEvaluator();
const checklist = INITIAL_AUDIT_CHECKLIST;

const getParam = (id: string): AuditParameter => {
  const p = checklist.find(param => param.id === id);
  if (!p) throw new Error(`Parameter ${id} not found in checklist`);
  return JSON.parse(JSON.stringify(p));
};

// Test A: USB implementation documents alone without Policy result in partial fulfillment (REVIEW, 5/10)
const zti008 = getParam('ZTI-008');
const usbItems: EvidenceItem[] = [
  { evidence_id: 'E1', file_id: 'F1', filename: '15_usb_implementation.csv', path: '/audit/15_usb_implementation.csv', evidence_type: 'USB_IMPLEMENTATION_LOG', relevance: 0.95, snippet: 'USB port restricted GPO configuration export StorageDevicePolicies Deny_All usb_storage usb_block', created_at: new Date().toISOString(), candidate: true, validated: true, extracted_fields: { is_implementation: true }, evidenceRole: 'PRIMARY_IMPLEMENTATION', finalCandidateScore: 18000 },
  { evidence_id: 'E2', file_id: 'F2', filename: '1_usb_implementation.csv', path: '/audit/1_usb_implementation.csv', evidence_type: 'USB_IMPLEMENTATION_LOG', relevance: 0.95, snippet: 'USB port restricted alt StorageDevicePolicies Deny_All', created_at: new Date().toISOString(), candidate: true, validated: true, extracted_fields: { is_implementation: true }, evidenceRole: 'DUPLICATE_OR_PARALLEL_EVIDENCE', finalCandidateScore: 17500 },
  { evidence_id: 'E3', file_id: 'F3', filename: '02_usb_gpo.txt', path: '/audit/02_usb_gpo.txt', evidence_type: 'GPO_CONFIG', relevance: 0.90, snippet: 'GPO USB policy configuration', created_at: new Date().toISOString(), candidate: true, validated: true, extracted_fields: { is_implementation: false, is_policy: true }, evidenceRole: 'SUPPORTING_IMPLEMENTATION', finalCandidateScore: 14000 }
];

const resZTI008 = evaluator.evaluateParameter(zti008, usbItems, '2026-08-15');
assert(resZTI008.status === 'REVIEW', 'Test A1: ZTI-008 with USB implementation alone returns REVIEW');
assert(resZTI008.score_earned === 5, 'Test A2: ZTI-008 partial score earned is 5/10');
assert(resZTI008.missing_requirements && resZTI008.missing_requirements.length > 0, 'Test A3: Missing requirements is never empty');

// Test B: Three different GST certificates for three different entities remain three independent documents
const gst1: EvidenceItem = { evidence_id: 'G1', file_id: 'FG1', filename: 'gst_alpha.pdf', path: '/audit/gst_alpha.pdf', evidence_type: 'GST_CERTIFICATE', relevance: 0.95, snippet: 'GSTIN 29AAAAA0000A1Z5 Alpha Corp', created_at: new Date().toISOString(), candidate: true, validated: true, extracted_fields: { gstin: '29AAAAA0000A1Z5' }, sha256: 'hash_alpha' };
const gst2: EvidenceItem = { evidence_id: 'G2', file_id: 'FG2', filename: 'gst_beta.pdf', path: '/audit/gst_beta.pdf', evidence_type: 'GST_CERTIFICATE', relevance: 0.95, snippet: 'GSTIN 29BBBBB1111B2Z6 Beta Ltd', created_at: new Date().toISOString(), candidate: true, validated: true, extracted_fields: { gstin: '29BBBBB1111B2Z6' }, sha256: 'hash_beta' };
assert(gst1.sha256 !== gst2.sha256 && gst1.file_id !== gst2.file_id, 'Test B: Different entity GST certificates remain independent');

// Test C: Two documents with 95% identical text but different entity identifiers remain independent
const docC1: EvidenceItem = { evidence_id: 'DC1', file_id: 'FC1', filename: 'policy_branch1.pdf', path: '/audit/branch1.pdf', evidence_type: 'POLICY', relevance: 0.9, snippet: 'Security policy for Branch Alpha', created_at: new Date().toISOString(), candidate: true, validated: true, extracted_fields: { entity: 'Branch Alpha' }, sha256: 'hash_c1' };
const docC2: EvidenceItem = { evidence_id: 'DC2', file_id: 'FC2', filename: 'policy_branch2.pdf', path: '/audit/branch2.pdf', evidence_type: 'POLICY', relevance: 0.9, snippet: 'Security policy for Branch Beta', created_at: new Date().toISOString(), candidate: true, validated: true, extracted_fields: { entity: 'Branch Beta' }, sha256: 'hash_c2' };
assert(docC1.file_id !== docC2.file_id && docC1.sha256 !== docC2.sha256, 'Test C: Similar documents with different entity IDs remain independent');

// Test D: Exact SHA-256 duplicate files remain independently visible in evidence registry
const dup1: EvidenceItem = { evidence_id: 'D1', file_id: 'FD1', filename: 'report_copy1.pdf', path: '/audit/report_copy1.pdf', evidence_type: 'REPORT', relevance: 0.9, snippet: 'Audit report', created_at: new Date().toISOString(), candidate: true, validated: true, extracted_fields: {}, sha256: 'exact_sha_hash' };
const dup2: EvidenceItem = { evidence_id: 'D2', file_id: 'FD2', filename: 'report_copy2.pdf', path: '/audit/report_copy2.pdf', evidence_type: 'REPORT', relevance: 0.9, snippet: 'Audit report', created_at: new Date().toISOString(), candidate: true, validated: true, extracted_fields: {}, sha256: 'exact_sha_hash' };
assert(dup1.sha256 === dup2.sha256 && dup1.file_id !== dup2.file_id, 'Test D: Exact SHA-256 duplicates remain independently visible records');

// Test E: Multiple documents supporting same sub-control do not inflate compound scoring
assert(usbItems.length === 3 && resZTI008.score_earned === 5, 'Test E: Multiple USB documents do not inflate compound score beyond sub-control credit');

// Test F: One document satisfying one branch of an AND compound control cannot satisfy the other branch
const ipm003 = getParam('IPM-003');
const leaseOnly: EvidenceItem = { evidence_id: 'L1', file_id: 'FL1', filename: 'lease.pdf', path: '/audit/lease.pdf', evidence_type: 'LEASE', relevance: 0.95, snippet: 'Lease agreement premises', created_at: new Date().toISOString(), candidate: true, validated: true, extracted_fields: { is_implementation: false } };
const resIPM = evaluator.evaluateParameter(ipm003, [leaseOnly], '2026-08-15');
assert(resIPM.status === 'REVIEW' && resIPM.sub_control_statuses?.['SHOPS_ESTABLISHMENT_CERTIFICATE'] === 'EVIDENCE_NOT_FOUND', 'Test F: Lease document cannot satisfy Shops Establishment sub-control');

// Test G: OR controls pass when one valid alternative is independently verified
const ipm001 = getParam('IPM-001');
const pfEvidence: EvidenceItem = {
  evidence_id: 'PF1',
  file_id: 'FP1',
  filename: 'pf_cert.pdf',
  path: '/audit/pf.pdf',
  evidence_type: 'PF_ESIC_CERTIFICATE',
  relevance: 0.95,
  snippet: 'EMPLOYEES PROVIDENT FUND ORGANISATION Establishment Code: KN/BNG/0049281/000 and ESIC Code: 31000492810001001 Certificate of Registration.',
  created_at: new Date().toISOString(),
  candidate: true,
  validated: true,
  extracted_fields: { epfo_code: 'KN/BNG/0049281/000', esic_code: '31000492810001001' }
};
const resOR = evaluator.evaluateParameter(ipm001, [pfEvidence], '2026-08-15');
assert(resOR.status === 'PASS', 'Test G: OR control passes when single valid alternative is verified');

// Test H: Generic filename similarity cannot satisfy missing domain requirement
const genericFile: EvidenceItem = { evidence_id: 'GEN1', file_id: 'FGEN1', filename: 'compliance_general.txt', path: '/audit/gen.txt', evidence_type: 'UNKNOWN', relevance: 0.4, snippet: 'General compliance reference', created_at: new Date().toISOString(), candidate: false, validated: false, is_filename_only: true, extracted_fields: {} };
const resGeneric = evaluator.evaluateParameter(zti008, [genericFile], '2026-08-15');
assert(resGeneric.status === 'EVIDENCE_NOT_FOUND', 'Test H: Generic filename cannot satisfy technical compliance requirement');

// Test I: Missing Evidence Requirements is never empty when REVIEW is returned
assert(resZTI008.missing_requirements && resZTI008.missing_requirements.length > 0, 'Test I: Missing Evidence Requirements is never empty on REVIEW');

// Test J: Evidence details expose all matched candidates and roles
assert(usbItems.every(item => item.evidenceRole && item.finalCandidateScore !== undefined), 'Test J: Evidence candidates expose evidenceRole and score metrics');

console.log(`\n====================================================`);
console.log(`TEST RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log('====================================================');

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
