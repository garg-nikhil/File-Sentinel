import fs from 'fs';

let content = fs.readFileSync('backend/audit/evidenceEngine.ts', 'utf8');

content = content.replace(
  "customChecklist?: AuditParameter[]",
  "customChecklist?: AuditParameter[],\n    aiPrivacyMode: 'OFF' | 'REDACTED_SNIPPETS' | 'FULL_TEXT' = 'OFF'"
);

const geminiCall = `      // Optional Gemini AI Assistance if evidence is found and review/assistance is required
      if (matchedEvidence.length > 0 && result.status !== 'PASS') {
        const topEvidence = matchedEvidence[0];
        const topFile = fileExtractions.find(f => f.fileId === topEvidence.file_id);
        if (topFile) {
          try {
            const aiRec = await evaluateEvidenceWithGemini(
              topEvidence.filename,
              topFile.extraction.text || '',
              param
            );
            if (aiRec) {
              result.ai_recommendation = aiRec;
            }
          } catch {
            // Silently fall back to deterministic evaluation result
          }
        }
      }`;

const newGeminiCall = `      // Optional Gemini AI Assistance
      if (aiPrivacyMode !== 'OFF' && result.evidence_set && (result.evidence_set.primaryEvidence || result.evidence_set.supportingEvidence.length > 0)) {
        try {
          const evidenceForAi = {
             primary: result.evidence_set.primaryEvidence,
             supporting: result.evidence_set.supportingEvidence,
             contradictory: result.evidence_set.contradictoryEvidence
          };
          
          let aiText = '';
          if (aiPrivacyMode === 'FULL_TEXT') {
            const topFile = fileExtractions.find(f => f.fileId === result.evidence_set?.primaryEvidence?.file_id);
            aiText = topFile?.extraction?.text || '';
          } else {
             aiText = JSON.stringify(evidenceForAi, null, 2);
          }

          const filename = result.evidence_set?.primaryEvidence?.filename || 'aggregated_evidence.json';

          const aiRec = await evaluateEvidenceWithGemini(
            filename,
            aiText,
            param
          );
          if (aiRec) {
            result.ai_recommendation = aiRec;
          }
        } catch {
          // Silently fall back to deterministic evaluation result
        }
      }`;

content = content.replace(geminiCall, newGeminiCall);

fs.writeFileSync('backend/audit/evidenceEngine.ts', content);
