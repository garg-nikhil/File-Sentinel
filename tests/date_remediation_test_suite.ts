import assert from 'node:assert';
import { DateEvaluator } from '../backend/audit/dateEvaluator.js';
import { EvidenceMatcher } from '../backend/audit/evidenceMatcher.js';
import { AuditEvaluator } from '../backend/audit/evaluator.js';
import { INITIAL_AUDIT_CHECKLIST } from '../backend/audit/checklist.js';
import { ExtractionResult } from '../backend/extractors/base.js';

function getParam(id: string) {
  const param = INITIAL_AUDIT_CHECKLIST.find(p => p.id === id);
  assert.ok(param, `Parameter ${id} must exist in checklist`);
  return param;
}

function createExtraction(text: string): ExtractionResult {
  return {
    text,
    metadata: {},
    links: [],
    embeddedObjects: [],
    structure: {},
    warnings: []
  };
}

export async function runDateRemediationTestSuite() {
  console.log('====================================================');
  console.log('   FileSentinel — Safe Date & Expiry Test Suite (Remediation 3)');
  console.log('====================================================\n');

  const matcher = new EvidenceMatcher();
  const evaluator = new AuditEvaluator();
  const auditDate = '2026-08-14';

  // ----------------------------------------------------
  // TEST 1: Explicit Expiry Date Recognition
  // ----------------------------------------------------
  console.log('[TEST 1] Explicit Expiry Date Recognition...');
  const text1 = 'Commercial General Liability Policy\nPolicy Number: CGL-99482\nExpiry Date: 31/03/2027';
  const res1 = DateEvaluator.extractDatesFromText(text1);
  assert.strictEqual(res1.expiryDate, '2027-03-31', 'Must parse 31/03/2027 to 2027-03-31');
  const expItem1 = res1.dateItems.find(d => d.type === 'EXPIRY_DATE');
  assert.ok(expItem1, 'Must contain dateItem of type EXPIRY_DATE');
  assert.strictEqual(expItem1?.value, '2027-03-31');
  console.log('  ✔ Correctly extracted explicit expiry date (2027-03-31) with EXPIRY_DATE semantic type.');

  // ----------------------------------------------------
  // TEST 2: Expired Insurance Policy Evaluation
  // ----------------------------------------------------
  console.log('\n[TEST 2] Expired Insurance Policy (IPM-004)...');
  const ipm004 = getParam('IPM-004');
  const text2 = `COMMERCIAL GENERAL LIABILITY INSURANCE POLICY
Insurer: National Insurance Corp
Policy Number: CGL-2026-559012
Insured Organization: Zenith Telecalling Services
Coverage Amount: $1,000,000 USD
Start Date: 2025-04-01
Expiry Date: 31/03/2026`;
  const evid2 = matcher.evaluateEvidence('f-ins-exp', 'CGL_Policy_Expired.txt', '/tmp/CGL_Policy_Expired.txt', ipm004, createExtraction(text2));
  assert.ok(evid2 !== null);
  assert.strictEqual(evid2.extracted_fields?.expiry_date, '2026-03-31');
  const eval2 = evaluator.evaluateParameter(ipm004, [evid2], auditDate);
  assert.strictEqual(eval2.status, 'FAIL', 'Expired insurance must evaluate to FAIL');
  assert.strictEqual(eval2.score_earned, 0, 'Score earned must be 0');
  assert.ok(eval2.reason.includes('expired on 2026-03-31'), 'Reason must explicitly state expiry date');
  console.log('  ✔ Correctly failed expired insurance policy (Status: FAIL, Expiry: 2026-03-31 vs Audit: 2026-08-14).');

  // ----------------------------------------------------
  // TEST 3: Valid Unexpired Insurance Policy Evaluation
  // ----------------------------------------------------
  console.log('\n[TEST 3] Valid Unexpired Insurance Policy (IPM-004)...');
  const text3 = `COMMERCIAL GENERAL LIABILITY INSURANCE POLICY
Insurer: National Insurance Corp
Policy Number: CGL-2026-559012
Insured Organization: Zenith Telecalling Services
Coverage Amount: $1,000,000 USD
Start Date: 2026-04-01
Expiry Date: 31/03/2027`;
  const evid3 = matcher.evaluateEvidence('f-ins-val', 'CGL_Policy_Valid.txt', '/tmp/CGL_Policy_Valid.txt', ipm004, createExtraction(text3));
  assert.ok(evid3 !== null);
  assert.strictEqual(evid3.extracted_fields?.expiry_date, '2027-03-31');
  const eval3 = evaluator.evaluateParameter(ipm004, [evid3], auditDate);
  assert.strictEqual(eval3.status, 'PASS', 'Valid unexpired insurance must evaluate to PASS');
  assert.strictEqual(eval3.score_earned, evaluator.calculateParameterMaxScore(ipm004), 'Full parameter score must be earned');
  console.log('  ✔ Correctly passed active unexpired insurance policy (Status: PASS, Expiry: 2027-03-31).');

  // ----------------------------------------------------
  // TEST 4: Missing Expiry on Insurance Policy (Requires Review)
  // ----------------------------------------------------
  console.log('\n[TEST 4] Missing Expiry Date on Insurance Policy (IPM-004)...');
  const text4 = `COMMERCIAL GENERAL LIABILITY INSURANCE POLICY
Insurer: National Insurance Corp
Policy Number: CGL-2026-559012
Insured Organization: Zenith Telecalling Services
Coverage Amount: $1,000,000 USD
Issue Date: 01/01/2026`;
  const evid4 = matcher.evaluateEvidence('f-ins-noexp', 'CGL_Policy_NoExpiry.txt', '/tmp/CGL_Policy_NoExpiry.txt', ipm004, createExtraction(text4));
  assert.ok(evid4 !== null);
  assert.strictEqual(evid4.extracted_fields?.expiry_date, undefined, 'Expiry date must be undefined when missing');
  const eval4 = evaluator.evaluateParameter(ipm004, [evid4], auditDate);
  assert.strictEqual(eval4.status, 'REVIEW', 'Insurance with missing expiry date must evaluate to REVIEW (never auto-PASS)');
  assert.strictEqual(eval4.score_earned, 0, 'Score earned must be 0 until reviewed');
  console.log('  ✔ Correctly flagged insurance policy with missing expiry date as REVIEW (not PASS).');

  // ----------------------------------------------------
  // TEST 5: Last-Date Trap (Prohibition of Fallback to Last Date)
  // ----------------------------------------------------
  console.log('\n[TEST 5] Last-Date Trap: Prohibit fallback to last document date...');
  const text5 = `Application Date: 10/07/2026
Review Date: 15/07/2026
Approved Date: 20/07/2026`;
  const res5 = DateEvaluator.extractDatesFromText(text5);
  assert.strictEqual(res5.applicationDate, '2026-07-10');
  assert.strictEqual(res5.reviewDate, '2026-07-15');
  assert.strictEqual(res5.expiryDate, undefined, 'CRITICAL: expiryDate MUST be undefined (must NOT take 20/07/2026 as expiry)');
  assert.deepStrictEqual(res5.allDates, ['2026-07-10', '2026-07-15', '2026-07-20']);
  console.log('  ✔ Confirmed: Last date in document (20/07/2026) is strictly NOT treated as expiry.');

  // ----------------------------------------------------
  // TEST 6: Policy Review Date (Must NOT be treated as Expiry)
  // ----------------------------------------------------
  console.log('\n[TEST 6] Policy Review Date semantic classification...');
  const text6 = `Information Security Policy v2.1
Effective Date: 01/01/2026
Review Date: 01/01/2027`;
  const res6 = DateEvaluator.extractDatesFromText(text6);
  assert.strictEqual(res6.effectiveDate, '2026-01-01');
  assert.strictEqual(res6.reviewDate, '2027-01-01');
  assert.strictEqual(res6.expiryDate, undefined, 'Review date must NOT be populated as expiryDate');
  const reviewItem6 = res6.dateItems.find(d => d.type === 'REVIEW_DATE');
  assert.ok(reviewItem6, 'Must contain dateItem of type REVIEW_DATE');
  console.log('  ✔ Correctly classified Review Date as REVIEW_DATE (expiryDate remains undefined).');

  // ----------------------------------------------------
  // TEST 7: Explicit Coverage Range Extraction
  // ----------------------------------------------------
  console.log('\n[TEST 7] Explicit Coverage Range extraction...');
  const text7 = 'Commercial Liability Policy CGL-8819\nCoverage: 01/04/2026 - 31/03/2027\nInsured: Zenith Agency';
  const res7 = DateEvaluator.extractDatesFromText(text7);
  assert.strictEqual(res7.effectiveDate, '2026-04-01', 'Range start must be effectiveDate');
  assert.strictEqual(res7.expiryDate, '2027-03-31', 'Range end must be expiryDate');
  console.log('  ✔ Correctly extracted date range: Effective (2026-04-01) and Expiry (2027-03-31).');

  // ----------------------------------------------------
  // TEST 8: Police Verification "Applied for" Branch (ZTI-005)
  // ----------------------------------------------------
  console.log('\n[TEST 8] Police Verification "Applied for" Branch (ZTI-005)...');
  const zti005 = getParam('ZTI-005');
  const text8 = `STATE POLICE DEPARTMENT - CHARACTER & BACKGROUND CLEARANCE
Application Type: Police Verification Report (PV)
Employee: John Smith
Status: APPLIED
Acknowledgement Slip Number: PV-ACK-2026-8812
Date of Application: 10/07/2026`;
  const evid8 = matcher.evaluateEvidence('f-pv-app', 'PV_Application_John.txt', '/tmp/PV_Application_John.txt', zti005, createExtraction(text8));
  assert.ok(evid8 !== null);
  assert.strictEqual(evid8.extracted_fields?.application_date, '2026-07-10');
  assert.strictEqual(evid8.extracted_fields?.expiry_date, undefined, 'Application proof does not require expiry date');
  const eval8 = evaluator.evaluateParameter(zti005, [evid8], auditDate);
  assert.strictEqual(eval8.status, 'PASS', 'Valid "Applied for" branch must PASS without requiring expiry date');
  assert.strictEqual(eval8.pv_status, 'APPLIED');
  assert.strictEqual(eval8.score_earned, evaluator.calculateParameterMaxScore(zti005), 'Full parameter score earned');
  console.log('  ✔ Police verification application proof successfully PASSED under "Applied for" branch with no expiry required.');

  // ----------------------------------------------------
  // TEST 9: Fire Drill within One Year (Recency Check PASS)
  // ----------------------------------------------------
  console.log('\n[TEST 9] Fire Drill within 1 year (IPM-008 PASS)...');
  const ipm008 = getParam('IPM-008');
  const text9 = `AGENCY ANNUAL FIRE SAFETY DRILL REPORT
Location: Main Operations Bay
Conducted on: 01/06/2026
Total Participants: 42 agents
Evacuation Time: 2 minutes 45 seconds
Fire Safety Officer: Capt. R. Sharma
Status: COMPLETED`;
  const evid9 = matcher.evaluateEvidence('f-drill-pass', 'Fire_Drill_2026.txt', '/tmp/Fire_Drill_2026.txt', ipm008, createExtraction(text9));
  assert.ok(evid9 !== null);
  assert.strictEqual(evid9.extracted_fields?.drill_date, '2026-06-01');
  const eval9 = evaluator.evaluateParameter(ipm008, [evid9], auditDate);
  assert.strictEqual(eval9.status, 'PASS', 'Drill conducted 2.5 months prior to audit must PASS');
  assert.strictEqual(eval9.score_earned, evaluator.calculateParameterMaxScore(ipm008));
  console.log('  ✔ Fire drill conducted on 2026-06-01 (Audit: 2026-08-14) evaluated as PASS (Recency < 1 year).');

  // ----------------------------------------------------
  // TEST 10: Fire Drill Older than One Year (Recency Check FAIL)
  // ----------------------------------------------------
  console.log('\n[TEST 10] Fire Drill older than 1 year (IPM-008 FAIL)...');
  const text10 = `AGENCY ANNUAL FIRE SAFETY DRILL REPORT
Location: Main Operations Bay
Conducted on: 01/01/2025
Total Participants: 38 agents
Status: COMPLETED`;
  const evid10 = matcher.evaluateEvidence('f-drill-fail', 'Fire_Drill_2025.txt', '/tmp/Fire_Drill_2025.txt', ipm008, createExtraction(text10));
  assert.ok(evid10 !== null);
  assert.strictEqual(evid10.extracted_fields?.drill_date, '2025-01-01');
  const eval10 = evaluator.evaluateParameter(ipm008, [evid10], auditDate);
  assert.strictEqual(eval10.status, 'FAIL', 'Drill conducted > 1 year prior to audit must FAIL');
  assert.strictEqual(eval10.score_earned, 0);
  assert.ok(eval10.reason.includes('older than 1 year'), 'Reason must indicate drill is older than 1 year');
  console.log('  ✔ Fire drill conducted on 2025-01-01 (Audit: 2026-08-14) correctly evaluated as FAIL (Recency > 1 year).');

  // ----------------------------------------------------
  // TEST 11: GST Registration Certificate (No Expiry Required)
  // ----------------------------------------------------
  console.log('\n[TEST 11] GST Registration Certificate without Expiry (ZTI-001 PASS)...');
  const zti001 = getParam('ZTI-001');
  const text11 = `GOVERNMENT OF INDIA - GOODS AND SERVICES TAX
Registration Certificate
Legal Name: Zenith Telecalling Services Private Limited
GSTIN: 27AAACF1234F1Z5
Date of Issue: 15/01/2024`;
  const evid11 = matcher.evaluateEvidence('f-gst', 'GST_Certificate.txt', '/tmp/GST_Certificate.txt', zti001, createExtraction(text11));
  assert.ok(evid11 !== null);
  assert.strictEqual(evid11.extracted_fields?.expiry_date, undefined, 'GST has no expiry date');
  const eval11 = evaluator.evaluateParameter(zti001, [evid11], auditDate);
  assert.strictEqual(eval11.status, 'PASS', 'GST does not require expiry date and must PASS');
  assert.strictEqual(eval11.score_earned, evaluator.calculateParameterMaxScore(zti001));
  console.log('  ✔ Valid GST certificate without expiry correctly evaluated as PASS.');

  // ----------------------------------------------------
  // TEST 12: Business Continuity Plan with Review Date Only (IPM-010)
  // ----------------------------------------------------
  console.log('\n[TEST 12] Business Continuity Plan with Review Date Only (IPM-010 PASS)...');
  const ipm010 = getParam('IPM-010');
  const text12 = `BUSINESS CONTINUITY AND DISASTER RECOVERY PLAN
Document Version: 3.0
Effective Date: 2026-01-10
Review Date: 2026-12-15
Approval Status: Approved by Board of Directors
Scope: All Agency Telecalling and Core Infrastructure Operations`;
  const evid12 = matcher.evaluateEvidence('f-bcp', 'BCP_Plan.txt', '/tmp/BCP_Plan.txt', ipm010, createExtraction(text12));
  assert.ok(evid12 !== null);
  assert.strictEqual(evid12.extracted_fields?.review_date, '2026-12-15');
  assert.strictEqual(evid12.extracted_fields?.expiry_date, undefined, 'BCP review date is not an expiry date');
  const eval12 = evaluator.evaluateParameter(ipm010, [evid12], auditDate);
  assert.strictEqual(eval12.status, 'PASS', 'BCP policy with review date evaluates as PASS');
  assert.strictEqual(eval12.score_earned, evaluator.calculateParameterMaxScore(ipm010));
  console.log('  ✔ BCP document evaluated as PASS; review date was NOT falsely treated as expiry.');

  // ----------------------------------------------------
  // TEST 13: Ambiguous or Invalid Date String Handling
  // ----------------------------------------------------
  console.log('\n[TEST 13] Ambiguous / Invalid Date String handling...');
  const text13 = 'Document Reference Number: 99/99/9999\nInvalid timestamp: 2026-99-99\nRandom string: 12345';
  const res13 = DateEvaluator.extractDatesFromText(text13);
  assert.strictEqual(res13.expiryDate, undefined, 'Invalid date must never create expiry date');
  assert.strictEqual(res13.allDates.length, 0, 'No invalid date should be in allDates');
  console.log('  ✔ Ambiguous/malformed date strings cleanly rejected with zero false-positive extractions.');

  // ----------------------------------------------------
  // TEST 14: Multiple Semantic Dates with No Expiry
  // ----------------------------------------------------
  console.log('\n[TEST 14] Multiple Semantic Dates in Single Document...');
  const text14 = `Audit & Compliance Log
Date of Birth: 15/05/1990
Date of Issue: 10/01/2026
Effective Date: 15/01/2026
Review Date: 20/01/2026
Date of Renewal: 25/01/2026
Date of Audit: 30/01/2026`;
  const res14 = DateEvaluator.extractDatesFromText(text14);
  assert.strictEqual(res14.issueDate, '1990-05-15');
  assert.strictEqual(res14.effectiveDate, '2026-01-15');
  assert.strictEqual(res14.reviewDate, '2026-01-20');
  assert.strictEqual(res14.renewalDate, '2026-01-25');
  assert.strictEqual(res14.auditDate, '2026-01-30');
  assert.strictEqual(res14.expiryDate, undefined, 'CRITICAL: No expiry label -> expiryDate MUST be undefined');
  console.log('  ✔ Successfully mapped 5 distinct semantic date types with expiryDate strictly undefined.');

  console.log('\n====================================================');
  console.log('  ALL 14 SAFE DATE & EXPIRY TESTS PASSED (100%)     ');
  console.log('====================================================\n');
}

runDateRemediationTestSuite().then(() => {
  process.exit(0);
}).catch(err => {
  console.error('\n❌ Safe Date & Expiry Test Suite Failed:\n', err);
  process.exit(1);
});
