import path from 'node:path';
import crypto from 'node:crypto';
import { ExtractionResult } from '../extractors/base.js';
import { AuditParameter, EvidenceItem } from './models.js';
import { EvidenceValidator } from './evidenceValidator.js';

export class EvidenceMatcher {
  /**
   * Compatibility alias for evaluateEvidence
   */
  public evaluateEvidence(
    fileId: string,
    filename: string,
    filePath: string,
    parameter: AuditParameter,
    extraction: ExtractionResult
  ): EvidenceItem | null {
    return this.matchDocumentToParameter(fileId, filePath, extraction, parameter);
  }

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

    // 1. Stage 1: Candidate Discovery
    let filenameMatch = false;
    let contentMatch = false;
    let matchedKeywordsInFilename = 0;
    let matchedKeywordsInContent = 0;

    const allKeywords = new Set<string>();
    if (parameter.keywords) {
      for (const kw of parameter.keywords) {
        if (kw) allKeywords.add(kw);
      }
    }
    if (parameter.requirements) {
      for (const req of parameter.requirements) {
        if (req.keywords) {
          for (const k of req.keywords) if (k) allKeywords.add(k);
        }
        if (req.evidence_types) {
          for (const t of req.evidence_types) if (t) allKeywords.add(t.replace(/_/g, ' '));
        }
        if (req.name) allKeywords.add(req.name);
        if (req.title) allKeywords.add(req.title);
      }
    }
    if (parameter.sub_controls) {
      for (const sub of parameter.sub_controls) {
        if (sub) allKeywords.add(sub.replace(/_/g, ' '));
      }
    }

    for (const kw of allKeywords) {
      if (!kw || typeof kw !== 'string') continue;
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

    // Baseline threshold: Must have at least a filename match or content match to be a candidate
    if (!filenameMatch && !contentMatch) {
      return null;
    }

    const isFilenameOnly = filenameMatch && !contentMatch;
    const isContentOnly = contentMatch && !filenameMatch;
    const candidate = true;

    // 2. Stage 2: Evidence Classification & Validation
    const policyVsImpl = this.classifyPolicyVsImplementation(filename, text);
    let valRes = EvidenceValidator.validate(filename, text, parameter, policyVsImpl);

    // If parameter has sub-controls/requirements and general validation didn't validate, check sub-controls
    if (!valRes.validated && parameter.requirements && parameter.requirements.length > 0) {
      for (const req of parameter.requirements) {
        const subVal = EvidenceValidator.validateForSubControl(req.id, req.evidence_types, filename, text, policyVsImpl);
        if (subVal.validated) {
          valRes = {
            ...valRes,
            validated: true,
            confidence: subVal.confidence,
            fieldValidation: subVal.fieldValidation,
            metadataMatch: valRes.metadataMatch || subVal.metadataMatch,
            entityMatch: valRes.entityMatch || subVal.entityMatch,
            semanticMatch: true,
            detectedEvidenceType: subVal.detectedEvidenceType,
            validationReason: subVal.validationReason,
            missingMandatoryFields: subVal.missingMandatoryFields,
            extractedFields: { ...valRes.extractedFields, ...subVal.extractedFields }
          };
          break;
        }
      }
    }

    const fieldValidation = valRes.fieldValidation;
    const metadataMatch = valRes.metadataMatch;
    const entityMatch = valRes.entityMatch;
    const semanticMatch = valRes.semanticMatch;
    const validated = isFilenameOnly ? false : valRes.validated;
    const confidence = isFilenameOnly ? 0.40 : valRes.confidence;

    // 3. Stage 3: Control Satisfaction
    let satisfiesControl = false;
    if (isFilenameOnly) {
      satisfiesControl = parameter.allow_filename_only === true;
    } else if (validated || parameter.allow_keyword_only === true) {
      satisfiesControl = true;
    } else {
      satisfiesControl = false;
    }

    // Calculate overall relevance score
    const totalKw = parameter.keywords.length;
    let relevance = 0.40;
    if (isFilenameOnly) {
      relevance = 0.45;
    } else if (validated) {
      relevance = Math.min(0.99, Math.max(0.70, (matchedKeywordsInContent / totalKw) * 0.4 + (filenameMatch ? 0.15 : 0) + 0.45));
    } else {
      relevance = Math.min(0.59, Math.max(0.35, (matchedKeywordsInContent / totalKw) * 0.5));
    }

    // Context snippet construction
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

    const extractedFields: Record<string, any> = {
      ...valRes.extractedFields,
      raw_text: text,
      matched_keywords_count: matchedKeywordsInContent + matchedKeywordsInFilename,
      validation_reason: valRes.validationReason,
      missing_mandatory_fields: valRes.missingMandatoryFields,
      structure_warnings: extraction.warnings || [],
      candidate,
      filenameMatch,
      contentMatch,
      metadataMatch,
      entityMatch,
      fieldValidation,
      semanticMatch,
      isFilenameOnly,
      isContentOnly,
      validated,
      satisfiesControl,
      confidence,
      // Snake_case aliases for backwards compatibility
      filename_match: filenameMatch,
      content_match: contentMatch,
      metadata_match: metadataMatch,
      entity_match: entityMatch,
      field_validation: fieldValidation,
      semantic_match: semanticMatch,
      is_filename_only: isFilenameOnly,
      is_content_only: isContentOnly,
      satisfies_control: satisfiesControl
    };

    return {
      evidence_id: `EVID-${crypto.randomUUID().substring(0, 8)}`,
      file_id: fileId,
      filename,
      path: filePath,
      evidence_type: valRes.detectedEvidenceType,
      relevance: Number(relevance.toFixed(2)),
      extracted_fields: extractedFields,
      snippet,
      created_at: new Date().toISOString(),
      candidate,
      filenameMatch,
      contentMatch,
      metadataMatch,
      entityMatch,
      fieldValidation,
      semanticMatch,
      isFilenameOnly,
      isContentOnly,
      validated,
      satisfiesControl,
      confidence,
      // Snake_case aliases
      filename_match: filenameMatch,
      content_match: contentMatch,
      metadata_match: metadataMatch,
      entity_match: entityMatch,
      field_validation: fieldValidation,
      semantic_match: semanticMatch,
      is_filename_only: isFilenameOnly,
      is_content_only: isContentOnly,
      satisfies_control: satisfiesControl
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
}
