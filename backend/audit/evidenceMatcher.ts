import path from 'node:path';
import crypto from 'node:crypto';
import { ExtractionResult } from '../extractors/base.js';
import { AuditParameter, EvidenceItem } from './models.js';
import { DateEvaluator } from './dateEvaluator.js';

export class EvidenceMatcher {
  /**
   * Evaluates a single document against a specific audit parameter to see if it qualifies as evidence
   */
  public matchDocumentToParameter(
    fileId: string,
    filePath: string,
    extraction: ExtractionResult,
    parameter: AuditParameter
  ): EvidenceItem | null {
    const filename = path.basename(filePath);
    const text = extraction.text || '';
    const textLower = text.toLowerCase();
    const filenameLower = filename.toLowerCase();

    // 1. Multi-signal evidence evaluation
    let filenameMatch = false;
    let contentMatch = false;
    let metadataMatch = false;
    let entityMatch = false;
    let fieldValidation = false;
    let semanticMatch = false;

    let matchedKeywordsInFilename = 0;
    let matchedKeywordsInContent = 0;

    for (const kw of parameter.keywords) {
      const kwLower = kw.toLowerCase();
      if (filenameLower.includes(kwLower)) {
        matchedKeywordsInFilename++;
        filenameMatch = true;
      }
      if (textLower.includes(kwLower)) {
        matchedKeywordsInContent++;
        contentMatch = true;
      }
    }

    // Baseline threshold: Must have at least a filename match or content match
    if (!filenameMatch && !contentMatch) {
      return null;
    }

    const isFilenameOnly = filenameMatch && !contentMatch;
    const isCandidate = true;
    const satisfiesControl = contentMatch || (filenameMatch && parameter.allow_filename_only === true);

    // 2. Extract Structured Fields & Metadata
    const extractedDates = DateEvaluator.extractDatesFromText(text);
    const personName = this.extractPersonName(text);
    const policyVsImpl = this.classifyPolicyVsImplementation(filename, text);

    if (personName || extractedDates.issueDate || extractedDates.expiryDate) {
      metadataMatch = true;
    }

    // Specific entity extraction per parameter category
    const extractedFields: Record<string, any> = {
      person_name: personName,
      issue_date: extractedDates.issueDate,
      expiry_date: extractedDates.expiryDate,
      all_dates: extractedDates.allDates,
      is_policy: policyVsImpl.isPolicy,
      is_implementation: policyVsImpl.isImplementation,
      policy_type: policyVsImpl.type,
      matched_keywords_count: matchedKeywordsInContent + matchedKeywordsInFilename,
      structure_warnings: extraction.warnings || []
    };

    if (parameter.id === 'ZTI-001') {
      const gstinMatch = text.match(/\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z0-9]{1}Z[A-Z0-9]{1}\b/);
      if (gstinMatch) {
        extractedFields['gstin'] = gstinMatch[0];
        entityMatch = true;
        fieldValidation = true;
      }
    } else if (parameter.id === 'IPM-004') {
      const policyNoMatch = text.match(/\b(POL|INS|CGL)[-A-Z0-9]{5,15}\b/i);
      if (policyNoMatch) {
        extractedFields['policy_number'] = policyNoMatch[0];
        entityMatch = true;
        fieldValidation = true;
      }
    } else if (parameter.id === 'ZTI-004') {
      const certMatch = text.match(/\b(DRA|CERT|NBFET)[-A-Z0-9]{4,12}\b/i);
      if (certMatch) {
        extractedFields['certificate_number'] = certMatch[0];
        entityMatch = true;
        fieldValidation = true;
      }
    }

    if (personName) {
      entityMatch = true;
    }

    const totalKw = parameter.keywords.length;
    const keywordRatio = (matchedKeywordsInContent + matchedKeywordsInFilename) / totalKw;
    semanticMatch = keywordRatio > 0.2;

    // Calculate relevance score
    let relevance = 0.4;
    if (isFilenameOnly) {
      relevance = 0.45; // Low relevance for filename-only candidates
    } else {
      relevance = Math.min(0.99, Math.max(0.5, (matchedKeywordsInContent / totalKw) * 0.7 + (filenameMatch ? 0.15 : 0) + 0.2));
    }

    // Build snippet context showing match
    const matchedKw = parameter.keywords.find(kw => textLower.includes(kw.toLowerCase())) || parameter.keywords[0];
    const kwIdx = textLower.indexOf(matchedKw.toLowerCase());
    let snippet = isFilenameOnly
      ? `Filename candidate match: '${filename}'. Document body content did not match parameter keywords.`
      : `Matched evidence keyword: '${matchedKw}'`;
    if (kwIdx !== -1) {
      const start = Math.max(0, kwIdx - 50);
      const end = Math.min(text.length, kwIdx + matchedKw.length + 80);
      snippet = `...${text.substring(start, end).replace(/[\r\n]+/g, ' ')}...`;
    }

    extractedFields['candidate'] = isCandidate;
    extractedFields['satisfies_control'] = satisfiesControl;
    extractedFields['is_filename_only'] = isFilenameOnly;
    extractedFields['filename_match'] = filenameMatch;
    extractedFields['content_match'] = contentMatch;
    extractedFields['metadata_match'] = metadataMatch;
    extractedFields['entity_match'] = entityMatch;
    extractedFields['field_validation'] = fieldValidation;
    extractedFields['semantic_match'] = semanticMatch;

    return {
      evidence_id: `EVID-${crypto.randomUUID().substring(0, 8)}`,
      file_id: fileId,
      filename,
      path: filePath,
      evidence_type: parameter.required_evidence[0] || 'GENERIC_EVIDENCE',
      relevance: Number(relevance.toFixed(2)),
      extracted_fields: extractedFields,
      snippet,
      created_at: new Date().toISOString(),
      candidate: isCandidate,
      satisfies_control: satisfiesControl,
      filename_match: filenameMatch,
      content_match: contentMatch,
      metadata_match: metadataMatch,
      entity_match: entityMatch,
      field_validation: fieldValidation,
      semantic_match: semanticMatch,
      is_filename_only: isFilenameOnly
    };
  }

  /**
   * Distinguishes whether document text/filename represents a Policy vs Implementation evidence
   */
  public classifyPolicyVsImplementation(filename: string, text: string): {
    isPolicy: boolean;
    isImplementation: boolean;
    type: 'POLICY_ONLY' | 'IMPLEMENTATION_ONLY' | 'BOTH' | 'UNCLEAR';
  } {
    const combined = `${filename} ${text.substring(0, 2000)}`.toLowerCase();

    const policyKeywords = ['policy', 'procedure', 'standard operating procedure', 'sop', 'guideline', 'framework', 'mandate', 'draft', 'version 1.'];
    const implKeywords = ['screenshot', 'export', 'config', 'configuration', 'audit log', 'inspection tag', 'active ad export', 'wsus report', 'attendance log', 'system dump', 'register log', 'receipt', 'certificate', 'photo', 'proof'];

    let hasPolicy = policyKeywords.some(k => combined.includes(k));
    let hasImpl = implKeywords.some(k => combined.includes(k));

    let type: 'POLICY_ONLY' | 'IMPLEMENTATION_ONLY' | 'BOTH' | 'UNCLEAR' = 'UNCLEAR';
    if (hasPolicy && hasImpl) type = 'BOTH';
    else if (hasPolicy) type = 'POLICY_ONLY';
    else if (hasImpl) type = 'IMPLEMENTATION_ONLY';

    return {
      isPolicy: hasPolicy,
      isImplementation: hasImpl,
      type
    };
  }

  /**
   * Helper to extract person/employee names from text
   */
  private extractPersonName(text: string): string | undefined {
    const nameMatch = text.match(/(?:Employee|Agent|Director|VP|Staff|Name|User):\s*([A-Z][a-z]+\s+[A-Z][a-z]+)/);
    if (nameMatch) {
      return nameMatch[1];
    }
    const genericNameMatch = text.match(/\b([A-Z][a-z]{2,15}\s+[A-Z][a-z]{2,15})\b/);
    if (genericNameMatch) {
      return genericNameMatch[1];
    }
    return undefined;
  }
}
