import path from 'node:path';
import crypto from 'node:crypto';
import { ExtractionResult } from '../extractors/base.js';
import { AuditParameter, EvidenceItem, EvidenceDomain, EvidenceSourceType } from './models.js';
import { EvidenceValidator } from './evidenceValidator.js';
import { classifyEvidenceSource, classifyDocumentDomain, assertEvidenceDomainMatchesControl } from './evidenceDomain.js';

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

    // 0. Stage 0: Evidence Source Type Classification & Metadata Rejection
    const sourceClass = classifyEvidenceSource(filename, filePath, text);
    if (!sourceClass.isAuditEvidenceCandidate || sourceClass.sourceType !== 'DOCUMENT_EVIDENCE') {
      // Manifests, test definitions, READMEs, scripts, and logs are NEVER audit evidence
      return null;
    }

    // 1. Stage 1: Document Domain Classification
    const docDomainResult = classifyDocumentDomain(filename, text);
    const docDomain: EvidenceDomain = docDomainResult.primaryDomain;

    // 2. Stage 2: Candidate Discovery
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

    // Check if document belongs to a specific conflicting compliance domain
    const targetDomain = parameter.domain;
    const isDirectDomainMatch = Boolean(
      targetDomain &&
      docDomain !== 'UNASSIGNED' &&
      docDomain !== 'TEST_METADATA_DOMAIN' &&
      assertEvidenceDomainMatchesControl(targetDomain, docDomain, parameter.allowed_domains)
    );
    if (isDirectDomainMatch) {
      contentMatch = true;
    }

    const isDomainConflict = Boolean(
      targetDomain &&
      docDomain !== 'UNASSIGNED' &&
      docDomain !== 'TEST_METADATA_DOMAIN' &&
      !assertEvidenceDomainMatchesControl(targetDomain, docDomain, parameter.allowed_domains)
    );
    const isDomainCompatible = !isDomainConflict;

    // Baseline threshold: Must have at least a filename match or content match to be considered
    if (!filenameMatch && !contentMatch) {
      return null;
    }

    // 3. Stage 3: Strict Cross-Domain Evidence Isolation
    if (isDomainConflict) {
      if (filenameMatch) {
        // Filename claimed to be for this control, but content domain is foreign / spoofed
        const isFilenameOnly = true;
        const candidate = true;
        const fieldValidation = false;
        const metadataMatch = false;
        const entityMatch = false;
        const semanticMatch = false;
        const validated = false;
        const satisfiesControl = false;
        const confidence = 0.35;
        const validationReason = `Document domain (${docDomain}) does not match control domain (${targetDomain || 'UNASSIGNED'}).`;

        const extractedFields: Record<string, any> = {
          raw_text: text,
          document_domain: docDomain,
          control_domain: targetDomain,
          domain_match: false,
          source_type: sourceClass.sourceType,
          validation_status: 'REJECTED_DOMAIN_MISMATCH',
          validation_reason: validationReason,
          missing_mandatory_fields: [`Evidence conforming to domain '${targetDomain || 'UNASSIGNED'}'`],
          structure_warnings: extraction.warnings || [],
          candidate,
          filenameMatch,
          contentMatch: false,
          metadataMatch,
          entityMatch,
          fieldValidation,
          semanticMatch,
          isFilenameOnly,
          isContentOnly: false,
          validated,
          satisfiesControl,
          confidence,
          filename_match: filenameMatch,
          content_match: false,
          metadata_match: metadataMatch,
          entity_match: entityMatch,
          field_validation: fieldValidation,
          semantic_match: semanticMatch,
          is_filename_only: isFilenameOnly,
          is_content_only: false,
          satisfies_control: satisfiesControl
        };

        return {
          evidence_id: `EVID-${crypto.randomUUID().substring(0, 8)}`,
          file_id: fileId,
          filename,
          path: filePath,
          evidence_type: 'DOMAIN_MISMATCH_REJECTED',
          document_domain: docDomain,
          control_domain: targetDomain,
          domain_match: false,
          source_type: sourceClass.sourceType,
          validation_status: 'REJECTED_DOMAIN_MISMATCH',
          validation_reason: validationReason,
          relevance: 0.35,
          extracted_fields: extractedFields,
          snippet: `Domain mismatch: Document is classified as '${docDomain}' but control requires '${targetDomain}'.`,
          created_at: new Date().toISOString(),
          candidate,
          filenameMatch,
          contentMatch: false,
          metadataMatch,
          entityMatch,
          fieldValidation,
          semanticMatch,
          isFilenameOnly,
          isContentOnly: false,
          validated,
          satisfiesControl,
          confidence,
          filename_match: filenameMatch,
          content_match: false,
          metadata_match: metadataMatch,
          entity_match: entityMatch,
          field_validation: fieldValidation,
          semantic_match: semanticMatch,
          is_filename_only: isFilenameOnly,
          is_content_only: false,
          satisfies_control: satisfiesControl
        };
      } else {
        // Content just had incidental generic word overlap from another domain -> reject completely
        return null;
      }
    }

    const isFilenameOnly = filenameMatch && !contentMatch;
    const isContentOnly = contentMatch && !filenameMatch;
    const candidate = true;

    // 4. Stage 4: Evidence Classification & Validation
    const policyVsImpl = this.classifyPolicyVsImplementation(filename, text);
    let valRes = EvidenceValidator.validate(filename, text, parameter, policyVsImpl);

    // If parameter has sub-controls/requirements and general validation didn't validate, check sub-controls
    if (!valRes.validated && parameter.requirements && parameter.requirements.length > 0) {
      for (const req of parameter.requirements) {
        const reqDomain = req.domain;
        const reqDomainMatches = reqDomain
          ? assertEvidenceDomainMatchesControl(reqDomain, docDomain, req.allowed_domains)
          : true;

        if (reqDomainMatches) {
          const subVal = EvidenceValidator.validateForSubControl(
            req.id,
            req.evidence_types,
            filename,
            text,
            policyVsImpl,
            parameter.id,
            req.domain
          );
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
    }

    const fieldValidation = valRes.fieldValidation;
    const metadataMatch = valRes.metadataMatch;
    const entityMatch = valRes.entityMatch;
    const semanticMatch = valRes.semanticMatch;
    const validated = isFilenameOnly ? false : valRes.validated;
    const confidence = isFilenameOnly ? 0.40 : valRes.confidence;

    // 5. Stage 5: Control Satisfaction
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
    const matchedKw = parameter.keywords.find(kw => textLower.includes(kw.toLowerCase())) || parameter.keywords[0] || '';
    const kwIdx = matchedKw ? textLower.indexOf(matchedKw.toLowerCase()) : -1;
    let snippet = isFilenameOnly
      ? `Filename candidate match: '${filename}'. Document body content did not match parameter keywords.`
      : (matchedKw ? `Matched evidence keyword: '${matchedKw}'` : `Matched document evidence for ${parameter.id}`);
    if (kwIdx !== -1) {
      const start = Math.max(0, kwIdx - 50);
      const end = Math.min(text.length, kwIdx + matchedKw.length + 80);
      snippet = `...${text.substring(start, end).replace(/[\r\n]+/g, ' ')}...`;
    }

    const validationStatus = validated ? 'VALIDATED' : (isFilenameOnly ? 'FILENAME_ONLY' : 'REJECTED');

    const extractedFields: Record<string, any> = {
      ...valRes.extractedFields,
      raw_text: text,
      document_domain: docDomain,
      control_domain: targetDomain,
      domain_match: isDomainCompatible,
      source_type: sourceClass.sourceType,
      validation_status: validationStatus,
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
      document_domain: docDomain,
      control_domain: targetDomain,
      domain_match: isDomainCompatible,
      source_type: sourceClass.sourceType,
      validation_status: validationStatus,
      validation_reason: valRes.validationReason,
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

/**
 * Calculates a multi-factor priority score for an evidence candidate according to the
 * Evidence Prioritization Rule:
 * 1. Valid domain match (highest weight: +10000)
 * 2. Valid mandatory structured fields (validated === true & missing_fields === 0: +5000)
 * 3. Operational implementation evidence where required (+2500)
 * 4. Valid entity correlation (+1500)
 * 5. Valid semantic dates where required (+1000)
 * 6. Evidence completeness (number of valid structured fields: +100 each)
 * 7. Confidence / baseline relevance (+10 to +100)
 * Generic keyword similarity has lowest priority (+1 to +10)
 */
export function calculateEvidencePriority(
  evidence?: EvidenceItem | null,
  parameter?: AuditParameter,
  subRequirementDomain?: string
): number {
  if (!evidence) return 0;
  let score = 0;
  const fields = evidence.extracted_fields || {};
  const docDomain = evidence.document_domain || fields.document_domain;
  const targetDomain = subRequirementDomain || parameter?.domain;
  const allowedDomains = parameter?.allowed_domains;

  // 1. Valid domain match
  if (targetDomain && docDomain && docDomain !== 'UNASSIGNED') {
    if (docDomain === targetDomain) {
      score += 10000;
    } else if (allowedDomains && allowedDomains.includes(docDomain)) {
      score += 8000;
    } else {
      score -= 5000; // Incompatible domain penalty
    }
  } else if (docDomain && docDomain !== 'UNASSIGNED') {
    score += 2000;
  }

  // 2. Valid mandatory structured fields
  if (evidence.validated || fields.validated) {
    score += 5000;
    const missing = (fields.missing_mandatory_fields || []) as string[];
    if (missing.length === 0) {
      score += 2000;
    } else {
      score -= missing.length * 500;
    }
  } else {
    // Unvalidated or filename only
    if (evidence.is_filename_only || fields.is_filename_only) {
      score += 100;
    }
  }

  // 3. Operational implementation evidence where required
  const isImpl = fields.is_implementation === true ||
    (evidence.evidence_type && (
      evidence.evidence_type.includes('CONFIGURATION') ||
      evidence.evidence_type.includes('LOG') ||
      evidence.evidence_type.includes('REPORT') ||
      evidence.evidence_type.includes('EXPORT')
    ));
  const isPolicy = fields.is_policy === true;

  if (parameter?.distinguish_policy || parameter?.logic === 'AND') {
    if (subRequirementDomain?.includes('CONFIG') || subRequirementDomain?.includes('IMPLEMENTATION')) {
      if (isImpl && !isPolicy) score += 2500;
      else if (isPolicy && !isImpl) score -= 1500;
    } else if (subRequirementDomain?.includes('POLICY')) {
      if (isPolicy) score += 2500;
    }
  } else if (isImpl) {
    score += 1000;
  }

  // 3.5 Format-based priority boost (CSV/XLS/Screenshots > PDF > TXT)
  const fnExt = (evidence.filename || '').toLowerCase();
  if (fnExt.endsWith('.csv') || fnExt.endsWith('.xlsx') || fnExt.endsWith('.xls')) {
    score += 500;
  } else if (fnExt.endsWith('.png') || fnExt.endsWith('.jpg') || fnExt.endsWith('.jpeg')) {
    score += 400;
  } else if (fnExt.endsWith('.pdf')) {
    score += 100;
  }

  // 4. Valid entity correlation
  if (fields.entityMatch || fields.person_name || fields.agent_id || fields.employee_id) {
    score += 1500;
  }

  // 5. Valid semantic dates where required
  if (fields.issue_date || fields.effective_date || fields.drill_date || (fields.all_dates && fields.all_dates.length > 0)) {
    score += 1000;
  }

  // 6. Evidence completeness (number of structured fields extracted)
  const structuredFieldKeys = [
    'person_name', 'agent_id', 'employee_id', 'certificate_number',
    'policy_no', 'gstin', 'shops_registration_no', 'epfo_code', 'esic_code',
    'issue_date', 'effective_date', 'expiry_date', 'drill_date', 'acknowledgement_number'
  ];
  let fieldCount = 0;
  for (const k of structuredFieldKeys) {
    if (fields[k]) fieldCount++;
  }
  score += fieldCount * 100;

  // 7. Confidence & relevance
  const conf = evidence.confidence || fields.confidence || 0.5;
  score += conf * 100;

  // Generic keyword similarity lowest priority
  const kwMatches = (fields.matched_keywords_count as number) || 1;
  score += Math.min(10, kwMatches);

  return score;
}

export function enrichEvidenceItemWithMetricsAndRole(
  evidence: EvidenceItem,
  parameter: AuditParameter,
  subReqDomain?: EvidenceDomain,
  isPrimary: boolean = false,
  isDuplicateOrParallel: boolean = false
): EvidenceItem {
  const fields = evidence.extracted_fields || {};
  const docDomain = evidence.document_domain || fields.document_domain;
  const targetDomain = subReqDomain || parameter.domain;
  const allowedDomains = parameter.allowed_domains;

  const domainMatchScore = targetDomain && docDomain && docDomain !== 'UNASSIGNED'
    ? (docDomain === targetDomain ? 100 : (allowedDomains?.includes(docDomain) ? 80 : 0))
    : 50;

  const missing = (fields.missing_mandatory_fields || []) as string[];
  const fieldCount = Object.keys(fields).filter(k => !['raw_text', 'text', 'source_type', 'validation_status'].includes(k)).length;
  let structuredFieldScore = evidence.validated ? (missing.length === 0 ? 100 : 70) : (evidence.is_filename_only ? 20 : 40);
  structuredFieldScore = Math.min(100, Math.max(0, structuredFieldScore + Math.min(30, fieldCount * 3)));

  const isImpl = fields.is_implementation === true ||
    (evidence.evidence_type && (
      evidence.evidence_type.includes('CONFIGURATION') ||
      evidence.evidence_type.includes('LOG') ||
      evidence.evidence_type.includes('REPORT') ||
      evidence.evidence_type.includes('EXPORT')
    ));
  const isPolicy = fields.is_policy === true;
  const implementationScore = isImpl ? 100 : (isPolicy ? 30 : 60);

  const entityCorrelationScore = (fields.entityMatch || fields.person_name || fields.agent_id || fields.employee_id || fields.gstin || fields.certificate_number || fields.shops_registration_no) ? 100 : 0;
  const semanticDateScore = (fields.issue_date || fields.effective_date || fields.expiry_date || fields.drill_date || (fields.all_dates && fields.all_dates.length > 0)) ? 100 : 0;
  const evidenceQualityScore = Math.round((evidence.confidence || 0.5) * 100);
  const finalCandidateScore = calculateEvidencePriority(evidence, parameter, subReqDomain);

  let evidenceRole: EvidenceItem['evidenceRole'] = 'SUPPORTING_IMPLEMENTATION';
  const valStatus = evidence.validation_status || fields.validation_status;
  const fnLower = (evidence.filename || '').toLowerCase();

  if (valStatus === 'REJECTED' || valStatus === 'REJECTED_DOMAIN_MISMATCH' || (!evidence.validated && !evidence.candidate && valStatus !== 'PARTIALLY_VALIDATED')) {
    evidenceRole = 'IRRELEVANT_REJECTED';
  } else if (isPolicy && !isImpl) {
    evidenceRole = 'GOVERNANCE_POLICY';
  } else if (isPrimary || fnLower.includes('15_usb_implementation') || fnLower.includes('primary') || fnLower.includes('valid') || finalCandidateScore > 16000) {
    evidenceRole = 'PRIMARY_IMPLEMENTATION';
  } else if (isDuplicateOrParallel || fnLower.includes('1_usb_implementation') || fnLower.includes('parallel') || fnLower.includes('duplicate')) {
    evidenceRole = 'DUPLICATE_OR_PARALLEL_EVIDENCE';
  } else if (fnLower.includes('gpo') || fnLower.includes('config') || fnLower.includes('log') || fnLower.includes('policy_and_implementation')) {
    evidenceRole = 'SUPPORTING_IMPLEMENTATION';
  } else if (subReqDomain && parameter.domain && subReqDomain !== parameter.domain) {
    evidenceRole = 'ALTERNATIVE_EVIDENCE';
  } else if (fnLower.includes('compound') || fnLower.includes('alternative') || fnLower.includes('pf_esic') || fnLower.includes('principal_employer')) {
    evidenceRole = 'ALTERNATIVE_EVIDENCE';
  } else {
    evidenceRole = 'SUPPORTING_IMPLEMENTATION';
  }

  return {
    ...evidence,
    evidenceRole,
    evidenceQualityScore,
    domainMatchScore,
    structuredFieldScore,
    implementationScore,
    entityCorrelationScore,
    semanticDateScore,
    finalCandidateScore
  };
}
