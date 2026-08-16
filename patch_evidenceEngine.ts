import fs from 'fs';

let content = fs.readFileSync('backend/audit/evidenceEngine.ts', 'utf8');

const stripLogic = `
          // Sanitize evidence before saving to DB
          const sanitizedEvidence = res.evidence.map(e => {
            const safeItem = { ...e };
            if (safeItem.extracted_fields) {
               safeItem.extracted_fields = { ...safeItem.extracted_fields };
               delete safeItem.extracted_fields.raw_text;
               delete safeItem.extracted_fields.fullText;
               delete safeItem.extracted_fields.documentText;
               delete safeItem.extracted_fields.extractedText;
               delete safeItem.extracted_fields.text;
            }
            if (safeItem.structured_fields) {
               safeItem.structured_fields = { ...safeItem.structured_fields };
               delete safeItem.structured_fields.raw_text;
               delete safeItem.structured_fields.fullText;
               delete safeItem.structured_fields.documentText;
               delete safeItem.structured_fields.extractedText;
               delete safeItem.structured_fields.text;
            }
            return safeItem;
          });

          // Also sanitize evidence_set
          let sanitizedEvidenceSet = undefined;
          if (res.evidence_set) {
            const sanitizeList = (list) => list.map(e => {
               const safeItem = { ...e };
               if (safeItem.extracted_fields) {
                  safeItem.extracted_fields = { ...safeItem.extracted_fields };
                  delete safeItem.extracted_fields.raw_text;
               }
               return safeItem;
            });
            sanitizedEvidenceSet = {
               ...res.evidence_set,
               primaryEvidence: res.evidence_set.primaryEvidence ? sanitizeList([res.evidence_set.primaryEvidence])[0] : null,
               supportingEvidence: sanitizeList(res.evidence_set.supportingEvidence || []),
               reviewEvidence: sanitizeList(res.evidence_set.reviewEvidence || []),
               contradictoryEvidence: sanitizeList(res.evidence_set.contradictoryEvidence || []),
               rejectedCandidates: sanitizeList(res.evidence_set.rejectedCandidates || [])
            };
          }

          paramStmt.run(
            session.audit_id,
            res.parameter_id,
            res.status,
            res.confidence,
            res.fatal ? 1 : 0,
            res.score_earned,
            res.max_score,
            res.policy_status || null,
            res.pv_status || null,
            JSON.stringify({ evidence: sanitizedEvidence, evidence_set: sanitizedEvidenceSet }),
            res.reason,
            JSON.stringify(res.missing_requirements),
            JSON.stringify(res.warnings),`;

content = content.replace(
  `          paramStmt.run(
            session.audit_id,
            res.parameter_id,
            res.status,
            res.confidence,
            res.fatal ? 1 : 0,
            res.score_earned,
            res.max_score,
            res.policy_status || null,
            res.pv_status || null,
            JSON.stringify(res.evidence),
            res.reason,
            JSON.stringify(res.missing_requirements),
            JSON.stringify(res.warnings),`,
  stripLogic
);

content = content.replace(
  "filePaths: string[],",
  "filePaths: string[]," // keep
);

fs.writeFileSync('backend/audit/evidenceEngine.ts', content);
