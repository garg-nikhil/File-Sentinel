import fs from 'fs';

let content = fs.readFileSync('backend/routes.ts', 'utf8');

content = content.replace(
  `        session = await evidenceEngine.runAuditScan(
          filePaths,
          audit_date || new Date().toISOString().split('T')[0],
          agency_name || 'Primary Telecalling & Collection Agency',
          auditor_name || 'Automated Compliance Inspector'
        );`,
  `        session = await evidenceEngine.runAuditScan(
          filePaths,
          audit_date || new Date().toISOString().split('T')[0],
          agency_name || 'Primary Telecalling & Collection Agency',
          auditor_name || 'Automated Compliance Inspector',
          undefined,
          currentSettings.aiPrivacyMode || 'OFF'
        );`
);

content = content.replace(
  "evidence: pr.evidence_json ? JSON.parse(pr.evidence_json) : [],",
  "evidence: pr.evidence_json ? (JSON.parse(pr.evidence_json).evidence || JSON.parse(pr.evidence_json)) : [],\n          evidence_set: pr.evidence_json && JSON.parse(pr.evidence_json).evidence_set ? JSON.parse(pr.evidence_json).evidence_set : undefined,"
);

// We should replace all occurrences of `evidence: pr.evidence_json ? JSON.parse(pr.evidence_json) : [],`
content = content.replace(/evidence: pr\.evidence_json \? JSON\.parse\(pr\.evidence_json\) : \[\],/g, "evidence: pr.evidence_json ? (JSON.parse(pr.evidence_json).evidence || JSON.parse(pr.evidence_json)) : [],\n          evidence_set: pr.evidence_json && JSON.parse(pr.evidence_json).evidence_set ? JSON.parse(pr.evidence_json).evidence_set : undefined,");

fs.writeFileSync('backend/routes.ts', content);
