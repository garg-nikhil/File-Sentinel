import assert from 'node:assert';
import { EntityResolver } from '../backend/audit/entityResolver.js';
import { AuditEvaluator } from '../backend/audit/evaluator.js';
import { EvidenceMatcher } from '../backend/audit/evidenceMatcher.js';
import { INITIAL_AUDIT_CHECKLIST } from '../backend/audit/checklist.js';
import { AuditParameter, AuditParameterResult, EvidenceItem } from '../backend/audit/models.js';
import { ExtractionResult } from '../backend/extractors/base.js';

function createMockExtraction(text: string): ExtractionResult {
  return {
    text,
    metadata: {},
    links: [],
    embeddedObjects: [],
    structure: {},
    warnings: []
  };
}

function createMockEvidenceItem(
  fileId: string,
  filename: string,
  paramId: string,
  text: string,
  overrides: Partial<EvidenceItem> = {}
): EvidenceItem {
  return {
    evidence_id: `EVID-${fileId}`,
    file_id: fileId,
    filename,
    path: `/tmp/${filename}`,
    evidence_type: 'DOCUMENT',
    relevance: 0.95,
    created_at: '2026-08-14T00:00:00.000Z',
    snippet: text,
    is_content_only: true,
    is_filename_only: false,
    validated: true,
    satisfies_control: true,
    confidence: 0.95,
    extracted_fields: {
      person_name: overrides.extracted_fields?.person_name,
      agent_id: overrides.extracted_fields?.agent_id,
      employee_id: overrides.extracted_fields?.employee_id,
      certificate_number: overrides.extracted_fields?.certificate_number,
      validation_reason: 'Documentary evidence validated with structured fields.',
      ...overrides.extracted_fields
    },
    ...overrides
  };
}

function createMockParamResult(
  param: AuditParameter,
  evidence: EvidenceItem[],
  status: 'PASS' | 'FAIL' | 'REVIEW' = 'PASS'
): AuditParameterResult {
  return {
    parameter_id: param.id,
    parameter: param,
    status,
    confidence: 0.95,
    fatal: param.fatal,
    score_earned: 10,
    max_score: 10,
    evidence,
    reason: 'Evidence validated',
    missing_requirements: [],
    warnings: []
  };
}

export async function runEntityResolutionTestSuite() {
  console.log('====================================================');
  console.log('   FileSentinel — Entity Resolution Test Suite      ');
  console.log('====================================================\n');

  const zti004 = INITIAL_AUDIT_CHECKLIST.find(p => p.id === 'ZTI-004')!; // DRA Certificate
  const zti005 = INITIAL_AUDIT_CHECKLIST.find(p => p.id === 'ZTI-005')!; // Police Verification
  const gci001 = INITIAL_AUDIT_CHECKLIST.find(p => p.id === 'GCI-001')!; // Agency ID Card
  const gci004 = INITIAL_AUDIT_CHECKLIST.find(p => p.id === 'GCI-004')!; // Refresher Training

  // TEST 1: Same exact person across multiple parameters
  console.log('[TEST 1] Same exact person across multiple parameters');
  const evid1_1 = createMockEvidenceItem('f1', 'DRA_Cert.pdf', 'ZTI-004', 'DRA Passed John Smith Agent ID: AG123', {
    extracted_fields: { person_name: 'John Smith', agent_id: 'AG123', certificate_number: 'DRA-99481' }
  });
  const evid1_2 = createMockEvidenceItem('f2', 'Police_Verif.pdf', 'ZTI-005', 'Police Verification John Smith Agent ID: AG123', {
    extracted_fields: { person_name: 'John Smith', agent_id: 'AG123' }
  });
  const evid1_3 = createMockEvidenceItem('f3', 'Agency_ID.pdf', 'GCI-001', 'Agency ID Card JOHN SMITH Agent ID: AG123', {
    extracted_fields: { person_name: 'JOHN SMITH', agent_id: 'AG123' }
  });
  const evid1_4 = createMockEvidenceItem('f4', 'Training_Sheet.csv', 'GCI-004', 'Refresher Training John Smith Agent ID: AG123', {
    extracted_fields: { person_name: 'John Smith', agent_id: 'AG123' }
  });

  const res1 = EntityResolver.resolveAuditSessionEntities([
    createMockParamResult(zti004, [evid1_1]),
    createMockParamResult(zti005, [evid1_2]),
    createMockParamResult(gci001, [evid1_3]),
    createMockParamResult(gci004, [evid1_4])
  ]);

  assert.strictEqual(res1.entities.length, 1, 'Should resolve to exactly 1 entity');
  assert.strictEqual(res1.entities[0].displayName, 'John Smith');
  assert.strictEqual(res1.entities[0].identifiers.agentId, 'AG123');
  assert.strictEqual(res1.entities[0].status, 'CONSISTENT');
  assert.strictEqual(res1.conflicts.length, 0, 'No conflicts expected');
  assert.strictEqual(res1.entities[0].evidenceReferences.length, 4, 'Should correlate all 4 evidence references');
  console.log('  ✔ Correctly resolved same person across 4 parameters into 1 consistent entity.');

  // TEST 2: Different legitimate people
  console.log('\n[TEST 2] Different legitimate people in agency');
  const evid2_1 = createMockEvidenceItem('f1', 'DRA_John.pdf', 'ZTI-004', 'John Smith AG123', {
    extracted_fields: { person_name: 'John Smith', agent_id: 'AG123' }
  });
  const evid2_2 = createMockEvidenceItem('f2', 'DRA_Jane.pdf', 'ZTI-004', 'Jane Doe AG124', {
    extracted_fields: { person_name: 'Jane Doe', agent_id: 'AG124' }
  });
  const evid2_3 = createMockEvidenceItem('f3', 'PV_Rahul.pdf', 'ZTI-005', 'Rahul Sharma AG125', {
    extracted_fields: { person_name: 'Rahul Sharma', agent_id: 'AG125' }
  });

  const res2 = EntityResolver.resolveAuditSessionEntities([
    createMockParamResult(zti004, [evid2_1, evid2_2]),
    createMockParamResult(zti005, [evid2_3])
  ]);

  assert.strictEqual(res2.entities.length, 3, 'Should create 3 distinct entities');
  assert.strictEqual(res2.conflicts.length, 0, 'Different people MUST NOT trigger false mismatch');
  assert.ok(res2.entities.every(e => e.status === 'CONSISTENT'), 'All entities should be CONSISTENT');
  console.log('  ✔ Correctly identified 3 distinct individuals with zero false mismatches.');

  // TEST 3: Same Agent ID + different names (Contradiction)
  console.log('\n[TEST 3] Same Agent ID + different names (Identity Conflict)');
  const evid3_1 = createMockEvidenceItem('f1', 'DRA_John.pdf', 'ZTI-004', 'John Smith Agent AG123', {
    extracted_fields: { person_name: 'John Smith', agent_id: 'AG123' }
  });
  const evid3_2 = createMockEvidenceItem('f2', 'PV_Jane.pdf', 'ZTI-005', 'Jane Doe Agent AG123', {
    extracted_fields: { person_name: 'Jane Doe', agent_id: 'AG123' }
  });

  const res3 = EntityResolver.resolveAuditSessionEntities([
    createMockParamResult(zti004, [evid3_1]),
    createMockParamResult(zti005, [evid3_2])
  ]);

  assert.ok(res3.conflicts.length >= 1, 'Should detect conflict for same Agent ID with conflicting names');
  assert.strictEqual(res3.conflicts[0].severity, 'REVIEW', 'Conflict must route to REVIEW (not hard fraud)');
  assert.ok(res3.conflicts[0].title.includes('POSSIBLE ENTITY MISMATCH') || res3.conflicts[0].title.includes('Conflicting Names'), 'Title should state POSSIBLE ENTITY MISMATCH');
  assert.strictEqual(res3.entityFindings.length, 1, 'Should create an audit-level entity finding');
  console.log('  ✔ Correctly detected Agent ID name conflict, routed to REVIEW with POSSIBLE ENTITY MISMATCH finding.');

  // TEST 4: Same Employee ID + different names
  console.log('\n[TEST 4] Same Employee ID + different names');
  const evid4_1 = createMockEvidenceItem('f1', 'DRA_John.pdf', 'ZTI-004', 'John Smith Employee ID: EMP-101', {
    extracted_fields: { person_name: 'John Smith', employee_id: 'EMP-101' }
  });
  const evid4_2 = createMockEvidenceItem('f2', 'PV_Jane.pdf', 'ZTI-005', 'Jane Doe Employee ID: EMP-101', {
    extracted_fields: { person_name: 'Jane Doe', employee_id: 'EMP-101' }
  });

  const res4 = EntityResolver.resolveAuditSessionEntities([
    createMockParamResult(zti004, [evid4_1]),
    createMockParamResult(zti005, [evid4_2])
  ]);

  assert.ok(res4.conflicts.length >= 1, 'Should detect conflict for same Employee ID with conflicting names');
  assert.strictEqual(res4.conflicts[0].severity, 'REVIEW');
  console.log('  ✔ Correctly detected Employee ID conflict, routed to REVIEW.');

  // TEST 5: Same name + different Agent IDs
  console.log('\n[TEST 5] Same name + different Agent IDs');
  const evid5_1 = createMockEvidenceItem('f1', 'DRA_John_1.pdf', 'ZTI-004', 'John Smith Agent ID: AG123', {
    extracted_fields: { person_name: 'John Smith', agent_id: 'AG123' }
  });
  const evid5_2 = createMockEvidenceItem('f2', 'DRA_John_2.pdf', 'ZTI-004', 'John Smith Agent ID: AG456', {
    extracted_fields: { person_name: 'John Smith', agent_id: 'AG456' }
  });

  const res5 = EntityResolver.resolveAuditSessionEntities([
    createMockParamResult(zti004, [evid5_1, evid5_2])
  ]);

  assert.strictEqual(res5.entities.length, 2, 'Should NOT falsely merge agents with different Agent IDs');
  assert.strictEqual(res5.conflicts.length, 0, 'No conflict generated between distinct agents');
  console.log('  ✔ Correctly kept agents with distinct Agent IDs as 2 separate entities without falsely merging them.');

  // TEST 6: Name capitalization differences
  console.log('\n[TEST 6] Name capitalization differences');
  const evid6_1 = createMockEvidenceItem('f1', 'Doc1.pdf', 'ZTI-004', 'John Smith AG123', {
    extracted_fields: { person_name: 'John Smith', agent_id: 'AG123' }
  });
  const evid6_2 = createMockEvidenceItem('f2', 'Doc2.pdf', 'GCI-001', 'JOHN SMITH AG123', {
    extracted_fields: { person_name: 'JOHN SMITH', agent_id: 'AG123' }
  });

  const res6 = EntityResolver.resolveAuditSessionEntities([
    createMockParamResult(zti004, [evid6_1]),
    createMockParamResult(gci001, [evid6_2])
  ]);

  assert.strictEqual(res6.entities.length, 1, 'Capitalization differences must resolve to same entity');
  assert.strictEqual(res6.entities[0].status, 'CONSISTENT');
  console.log('  ✔ Name capitalization differences safely normalized into single entity.');

  // TEST 7: Name punctuation differences (John A. Smith vs John A Smith)
  console.log('\n[TEST 7] Name punctuation differences (Middle Initial)');
  const evid7_1 = createMockEvidenceItem('f1', 'Doc1.pdf', 'ZTI-004', 'John A. Smith AG123', {
    extracted_fields: { person_name: 'John A. Smith', agent_id: 'AG123' }
  });
  const evid7_2 = createMockEvidenceItem('f2', 'Doc2.pdf', 'ZTI-005', 'John A Smith AG123', {
    extracted_fields: { person_name: 'John A Smith', agent_id: 'AG123' }
  });

  const res7 = EntityResolver.resolveAuditSessionEntities([
    createMockParamResult(zti004, [evid7_1]),
    createMockParamResult(zti005, [evid7_2])
  ]);

  assert.strictEqual(res7.entities.length, 1, 'Punctuation variations must resolve to same entity');
  assert.strictEqual(res7.entities[0].status, 'CONSISTENT');
  console.log('  ✔ Middle initial punctuation variations safely normalized into single entity.');

  // TEST 8: Fuzzy name only (Without strong identifiers)
  console.log('\n[TEST 8] Fuzzy name only (Without corroborating identifiers)');
  const evid8_1 = createMockEvidenceItem('f1', 'Doc1.pdf', 'ZTI-004', 'Jon Smith', {
    extracted_fields: { person_name: 'Jon Smith' }
  });
  const evid8_2 = createMockEvidenceItem('f2', 'Doc2.pdf', 'ZTI-005', 'John Smith', {
    extracted_fields: { person_name: 'John Smith' }
  });

  const res8 = EntityResolver.resolveAuditSessionEntities([
    createMockParamResult(zti004, [evid8_1]),
    createMockParamResult(zti005, [evid8_2])
  ]);

  assert.strictEqual(res8.entities.length, 2, 'Without strong identifier, fuzzy name variation must not be aggressively merged');
  console.log('  ✔ Fuzzy names without strong identifier safely kept distinct.');

  // TEST 9: Multiple agents with completely different names across categories
  console.log('\n[TEST 9] Multiple agents with completely different names across roster');
  const rosterEvid = [
    createMockEvidenceItem('f1', 'DRA_1.pdf', 'ZTI-004', 'Alice Cooper AG101', { extracted_fields: { person_name: 'Alice Cooper', agent_id: 'AG101' } }),
    createMockEvidenceItem('f2', 'DRA_2.pdf', 'ZTI-004', 'Bob Vance AG102', { extracted_fields: { person_name: 'Bob Vance', agent_id: 'AG102' } }),
    createMockEvidenceItem('f3', 'DRA_3.pdf', 'ZTI-004', 'Charlie Day AG103', { extracted_fields: { person_name: 'Charlie Day', agent_id: 'AG103' } }),
    createMockEvidenceItem('f4', 'PV_1.pdf', 'ZTI-005', 'Alice Cooper AG101', { extracted_fields: { person_name: 'Alice Cooper', agent_id: 'AG101' } })
  ];

  const res9 = EntityResolver.resolveAuditSessionEntities([
    createMockParamResult(zti004, [rosterEvid[0], rosterEvid[1], rosterEvid[2]]),
    createMockParamResult(zti005, [rosterEvid[3]])
  ]);

  assert.strictEqual(res9.entities.length, 3, 'Should create 3 entities for 3 distinct agents');
  assert.strictEqual(res9.conflicts.length, 0, 'No false mismatches across roster');
  console.log('  ✔ Agency roster correctly mapped to 3 entities with zero false conflicts.');

  // TEST 10: Invalid / rejected evidence must NOT create entity relationship
  console.log('\n[TEST 10] Invalid / rejected evidence excluded from entity resolution');
  const validEvid10 = createMockEvidenceItem('f1', 'Valid_DRA.pdf', 'ZTI-004', 'John Smith AG123', {
    validated: true,
    extracted_fields: { person_name: 'John Smith', agent_id: 'AG123' }
  });
  const invalidEvid10 = createMockEvidenceItem('f2', 'Rejected_Doc.pdf', 'ZTI-005', 'Jane Doe AG123', {
    validated: false,
    extracted_fields: { person_name: 'Jane Doe', agent_id: 'AG123', validated: false }
  });

  const res10 = EntityResolver.resolveAuditSessionEntities([
    createMockParamResult(zti004, [validEvid10]),
    createMockParamResult(zti005, [invalidEvid10], 'REVIEW')
  ]);

  assert.strictEqual(res10.entities.length, 1, 'Only validated evidence should create entity');
  assert.strictEqual(res10.entities[0].displayName, 'John Smith');
  assert.strictEqual(res10.conflicts.length, 0, 'Invalid evidence MUST NOT trigger entity conflict with valid evidence');
  console.log('  ✔ Rejected / unvalidated evidence safely excluded from entity correlation.');

  // TEST 11: Filename-only candidate must NOT participate in entity correlation
  console.log('\n[TEST 11] Filename-only candidate excluded from entity correlation');
  const validEvid11 = createMockEvidenceItem('f1', 'Valid_DRA.pdf', 'ZTI-004', 'John Smith AG123', {
    validated: true,
    is_filename_only: false,
    extracted_fields: { person_name: 'John Smith', agent_id: 'AG123' }
  });
  const filenameOnlyEvid11 = createMockEvidenceItem('f2', 'DRA_Jane_Doe.pdf', 'ZTI-005', 'Unrelated text body', {
    validated: false,
    is_filename_only: true,
    extracted_fields: { person_name: 'Jane Doe', agent_id: 'AG123', is_filename_only: true }
  });

  const res11 = EntityResolver.resolveAuditSessionEntities([
    createMockParamResult(zti004, [validEvid11]),
    createMockParamResult(zti005, [filenameOnlyEvid11], 'REVIEW')
  ]);

  assert.strictEqual(res11.entities.length, 1, 'Filename-only match must not create entity');
  assert.strictEqual(res11.conflicts.length, 0, 'Filename-only match must not trigger false entity conflict');
  console.log('  ✔ Filename-only evidence strictly excluded from entity correlation.');

  // TEST 12: TRUE CROSS-PARAMETER AUDIT SESSION PIPELINE TEST
  console.log('\n[TEST 12] TRUE CROSS-PARAMETER AUDIT SESSION PIPELINE TEST');
  const matcher = new EvidenceMatcher();
  const evaluator = new AuditEvaluator();

  // 1. ZTI-004: John Smith / AG123 DRA Certificate
  const draExtraction = createMockExtraction(
    'NATIONAL BANKING & FINANCIAL EDUCATION TRUST\n' +
    'CERTIFICATE OF COMPLETION - DRA TRAINED\n' +
    'Agent / Employee: John Smith\n' +
    'Agent ID: AG123\n' +
    'Certificate Number: DRA-2026-99481\n' +
    'Status: PASSED\n' +
    'Issue Date: 2026-06-12\n' +
    'Expiry Date: 2029-06-12\n'
  );
  const draEvidence = matcher.evaluateEvidence('f-dra', 'DRA_Certificate_John_Smith.txt', '/tmp/DRA_Certificate_John_Smith.txt', zti004, draExtraction);
  assert.ok(draEvidence !== null);
  const draResult = evaluator.evaluateParameter(zti004, [draEvidence], '2026-08-12');
  assert.strictEqual(draResult.status, 'PASS');

  // 2. ZTI-005: John Smith / AG123 Police Verification
  const pvExtraction = createMockExtraction(
    'STATE POLICE DEPARTMENT - CHARACTER & BACKGROUND CLEARANCE\n' +
    'Application Type: Police Verification Report (PV)\n' +
    'Employee: John Smith\n' +
    'Agent ID: AG123\n' +
    'Status: APPLIED\n' +
    'Acknowledgement Slip Number: PV-ACK-2026-8812\n' +
    'Date of Application: 10/07/2026\n'
  );
  const pvEvidence = matcher.evaluateEvidence('f-pv', 'Police_Verification_Acknowledgement.txt', '/tmp/Police_Verification_Acknowledgement.txt', zti005, pvExtraction);
  assert.ok(pvEvidence !== null);
  const pvResult = evaluator.evaluateParameter(zti005, [pvEvidence], '2026-08-12');
  assert.strictEqual(pvResult.status, 'PASS');

  // 3. GCI-001: John Smith / AG123 Valid Agency ID Card
  const idExtraction = createMockExtraction(
    'ZENITH AGENCY - FIELD IDENTIFICATION CARD\n' +
    'Agent Name: JOHN SMITH\n' +
    'Agent ID: AG123\n' +
    'Status: ACTIVE\n' +
    'Field Endorsement: VALID\n'
  );
  const idEvidence = matcher.evaluateEvidence('f-id', 'Agency_ID_Card.txt', '/tmp/Agency_ID_Card.txt', gci001, idExtraction);
  assert.ok(idEvidence !== null);
  const idResult = evaluator.evaluateParameter(gci001, [idEvidence], '2026-08-12');
  assert.strictEqual(idResult.status, 'PASS');

  // Run full session-level entity resolution
  const sessionResult = EntityResolver.resolveAuditSessionEntities([
    draResult,
    pvResult,
    idResult
  ], 'AUDIT-TEST-SESSION-001');

  console.log('DEBUG TEST 12 entities:', JSON.stringify(sessionResult.entities, null, 2));

  assert.strictEqual(sessionResult.entities.length, 1, 'Must correlate cross-parameter evidence into exactly 1 unified entity');
  const entity = sessionResult.entities[0];
  assert.strictEqual(entity.displayName, 'John Smith');
  assert.strictEqual(entity.identifiers.agentId, 'AG123');
  assert.strictEqual(entity.status, 'CONSISTENT');
  assert.strictEqual(entity.evidenceReferences.length, 3, 'Must reference all 3 parameters (ZTI-004, ZTI-005, GCI-001)');
  assert.strictEqual(sessionResult.conflicts.length, 0, 'Zero conflicts expected');

  const paramIds = entity.evidenceReferences.map(r => r.parameterId).sort();
  assert.deepStrictEqual(paramIds, ['GCI-001', 'ZTI-004', 'ZTI-005']);
  console.log('  ✔ Full cross-parameter pipeline successfully correlated ZTI-004, ZTI-005, and GCI-001 into ONE consistent entity (John Smith / AG123).');

  console.log('\n====================================================');
  console.log('  ALL 12 ENTITY RESOLUTION TESTS PASSED (100%)      ');
  console.log('====================================================');
}

runEntityResolutionTestSuite().then(() => {
  process.exit(0);
}).catch(err => {
  console.error('\n❌ Test Suite Failed:\n', err);
  process.exit(1);
});
