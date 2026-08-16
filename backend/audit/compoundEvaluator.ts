import { EvidenceAggregator } from './evidenceAggregator.js';
import {
  AuditParameter,
  AuditParameterResult,
  AuditParameterStatus,
  EvidenceItem,
  PolicyImplementationStatus,
  RequirementLogic,
  SubControlRequirement,
  SubControlResult
} from './models.js';
import { EvidenceValidator } from './evidenceValidator.js';
import { DateEvaluator } from './dateEvaluator.js';
import { assertEvidenceDomainMatchesControl } from './evidenceDomain.js';
import { calculateEvidencePriority, enrichEvidenceItemWithMetricsAndRole } from './evidenceMatcher.js';

export class CompoundEvaluator {
  /**
   * Evaluates a compound audit parameter against evidence items.
   * Handles AND, OR, GROUP, and arbitrary nested logic structures.
   * Enforces evidence isolation: Evidence for one sub-control cannot satisfy another.
   */
  public static evaluateCompoundParameter(
    parameter: AuditParameter,
    evidenceItems: EvidenceItem[],
    auditDate: string,
    calculateMaxScore: (param: AuditParameter) => number
  ): AuditParameterResult {
    const maxScore = calculateMaxScore(parameter);
    const requirements = this.resolveRequirements(parameter);

    if (requirements.length === 0) {
      // Fallback if no sub-controls are defined
      return {
        parameter_id: parameter.id,
        parameter,
        status: evidenceItems.length > 0 ? 'PASS' : 'EVIDENCE_NOT_FOUND',
        confidence: 0.85,
        fatal: parameter.fatal,
        score_earned: evidenceItems.length > 0 ? maxScore : 0,
        max_score: maxScore,
        evidence: evidenceItems,
        reason: evidenceItems.length > 0 ? 'Evidence identified' : 'No evidence found',
        missing_requirements: evidenceItems.length > 0 ? [] : ['Supporting evidence document'],
        warnings: []
      };
    }

    const logic: RequirementLogic = parameter.logic || 'AND';
    const subControlWeight = maxScore / requirements.length;

    // Evaluate each requirement independently
    const subResults: SubControlResult[] = requirements.map(req => {
      return this.evaluateRequirement(req, evidenceItems, auditDate, subControlWeight, parameter);
    });

    const subStatuses: Record<string, AuditParameterStatus> = {};
    for (const res of subResults) {
      subStatuses[res.id] = res.status;
    }

    // Aggregate overall status and score based on parameter logic
    const { finalStatus, scoreEarned, reason, missingRequirements, warnings } = this.aggregateResults(
      logic,
      parameter,
      subResults,
      maxScore
    );

    // Collect all matched evidence
    const usedEvidenceMap = new Map<string, EvidenceItem>();
    for (const sub of subResults) {
      for (const evid of sub.evidence) {
        usedEvidenceMap.set(evid.evidence_id || evid.filename, evid);
      }
    }
    // If no specific sub-evidence was linked but evidence exists, keep parameter level evidence
    const allEvidence = usedEvidenceMap.size > 0 ? Array.from(usedEvidenceMap.values()) : evidenceItems;

    const { evidenceSet } = EvidenceAggregator.aggregate(parameter, allEvidence);
    return {
      parameter_id: parameter.id,
      parameter,
      status: finalStatus,
      confidence: Number((subResults.reduce((acc, r) => acc + r.confidence, 0) / subResults.length).toFixed(2)),
      fatal: parameter.fatal,
      score_earned: scoreEarned,
      max_score: maxScore,
      sub_control_statuses: subStatuses,
      sub_control_results: subResults,
      children: subResults,
      evidence: allEvidence,
      evidence_set: evidenceSet,
      reason,
      missing_requirements: missingRequirements,
      warnings
    };
  }

  /**
   * Recursively evaluates a single requirement or nested requirement group
   */
  public static evaluateRequirement(
    req: SubControlRequirement,
    allEvidence: EvidenceItem[],
    auditDate: string,
    maxScore: number,
    parentParameter: AuditParameter
  ): SubControlResult {
    // 1. NESTED LOGIC EVALUATION
    if (req.logic && (req.requirements || req.sub_requirements) && ((req.requirements?.length || 0) > 0 || (req.sub_requirements?.length || 0) > 0)) {
      const nestedReqs = req.requirements || req.sub_requirements || [];
      const childWeight = maxScore / nestedReqs.length;
      const childResults = nestedReqs.map(child => this.evaluateRequirement(child, allEvidence, auditDate, childWeight, parentParameter));
      
      const { finalStatus, scoreEarned, reason, missingRequirements, warnings } = this.aggregateResults(
        req.logic,
        parentParameter,
        childResults,
        maxScore
      );

      const nestedEvidence = Array.from(new Set(childResults.flatMap(c => c.evidence)));

      return {
        id: req.id,
        name: req.name,
        description: req.description,
        status: finalStatus,
        score_earned: scoreEarned,
        max_score: maxScore,
        confidence: Number((childResults.reduce((a, c) => a + c.confidence, 0) / childResults.length).toFixed(2)),
        evidence: nestedEvidence,
        reason,
        missing_requirements: missingRequirements,
        warnings,
        sub_results: childResults
      };
    }

    // 2. LEAF SUB-CONTROL EVALUATION WITH EVIDENCE ISOLATION
    const matchingEvidence = this.findMatchingEvidenceForRequirement(req, allEvidence, parentParameter);

    if (matchingEvidence.length === 0) {
      return {
        id: req.id,
        name: req.name,
        description: req.description,
        status: 'EVIDENCE_NOT_FOUND',
        score_earned: 0,
        max_score: maxScore,
        confidence: 0.95,
        evidence: [],
        reason: `No acceptable documentary evidence found for requirement '${req.name}'.`,
        missing_requirements: [req.description || req.name]
      };
    }

    // Evaluate candidate evidence items against this specific sub-control
    const evaluatedItems = matchingEvidence.map(evid => {
      const isPolicy = Boolean(evid.extracted_fields?.is_policy);
      const isImplementation = Boolean(evid.extracted_fields?.is_implementation);
      const policyType = evid.extracted_fields?.policy_type || 'UNKNOWN';

      const docText = evid.extracted_fields?.raw_text || evid.extracted_fields?.text || evid.snippet || '';
      const validation = EvidenceValidator.validateForSubControl(
        req.id,
        req.evidence_types,
        evid.filename,
        docText,
        { isPolicy, isImplementation, type: policyType },
        parentParameter.id,
        req.domain
      );

      return {
        evidence: evid,
        validation
      };
    });

    const validatedItems = evaluatedItems.filter(item => item.validation.validated);

    if (validatedItems.length === 0) {
      // Evidence existed but failed structured sub-control validation
      const missingReason = evaluatedItems[0]?.validation.validationReason || `Document content failed structured validation for '${req.name}'.`;
      const missingFields = evaluatedItems[0]?.validation.missingMandatoryFields || [req.name];

      return {
        id: req.id,
        name: req.name,
        description: req.description,
        status: 'REVIEW',
        score_earned: 0,
        max_score: maxScore,
        confidence: 0.85,
        evidence: matchingEvidence,
        reason: missingReason,
        missing_requirements: missingFields,
        warnings: [`Candidate document failed ${req.name} validation rules`]
      };
    }

    // Check policy vs implementation requirement
    if (req.requires_implementation || (req.distinguish_policy && parentParameter.distinguish_policy)) {
      const hasImpl = validatedItems.some(i => i.evidence.extracted_fields?.is_implementation || i.validation.detectedEvidenceType.includes('CONFIGURATION') || i.validation.detectedEvidenceType.includes('LOG') || i.validation.detectedEvidenceType.includes('REPORT'));
      const isPolicyOnly = validatedItems.every(i => i.evidence.extracted_fields?.is_policy && !i.evidence.extracted_fields?.is_implementation);

      if (isPolicyOnly && !hasImpl) {
        return {
          id: req.id,
          name: req.name,
          description: req.description,
          status: 'REVIEW',
          score_earned: 0,
          max_score: maxScore,
          confidence: 0.90,
          evidence: validatedItems.map(i => i.evidence),
          reason: `Policy document identified for '${req.name}', but technical implementation evidence is required.`,
          missing_requirements: [`Operational implementation evidence for ${req.name}`],
          warnings: ['Policy document present without operational implementation']
        };
      }
    }

    // Check expiry / validity if required
    if (req.requires_validity_check || req.expiry_required) {
      const expiryDates = validatedItems
        .map(i => i.validation.extractedFields?.expiry_date || i.evidence.extracted_fields?.expiry_date)
        .filter((d): d is string => Boolean(d));

      if (expiryDates.length > 0) {
        const primaryExpiry = expiryDates[0];
        if (DateEvaluator.isExpired(primaryExpiry, auditDate)) {
          return {
            id: req.id,
            name: req.name,
            description: req.description,
            status: 'FAIL',
            score_earned: 0,
            max_score: maxScore,
            confidence: 0.98,
            evidence: validatedItems.map(i => i.evidence),
            reason: `Evidence for '${req.name}' expired on ${primaryExpiry} (audit date: ${auditDate}).`,
            missing_requirements: [`Active, unexpired evidence for ${req.name}`],
            warnings: [`Expired evidence document (${primaryExpiry})`]
          };
        }
      } else if (req.expiry_required) {
        return {
          id: req.id,
          name: req.name,
          description: req.description,
          status: 'REVIEW',
          score_earned: 0,
          max_score: maxScore,
          confidence: 0.85,
          evidence: validatedItems.map(i => i.evidence),
          reason: `Explicit expiry date required for '${req.name}', but no expiry date found.`,
          missing_requirements: [`Document with verified expiration date for ${req.name}`],
          warnings: ['Missing required expiry date']
        };
      }
    }

    // Prioritize exact domain match and implementation evidence for the sub-control
    validatedItems.sort((a, b) => {
      const priorityDiff = calculateEvidencePriority(b.evidence, undefined, req.domain) - calculateEvidencePriority(a.evidence, undefined, req.domain);
      if (priorityDiff !== 0) return priorityDiff;
      return b.validation.confidence - a.validation.confidence;
    });

    // Contradiction detection across validated items for this requirement
    const { evidenceSet, hasContradiction } = EvidenceAggregator.aggregate(
      { ...parentParameter, id: req.id },
      validatedItems.map(i => i.evidence)
    );

    if (hasContradiction) {
      return {
        id: req.id,
        name: req.name,
        description: req.description,
        status: 'REVIEW',
        score_earned: 0,
        max_score: maxScore,
        confidence: 0.80,
        evidence: validatedItems.map(i => i.evidence),
        reason: `Conflicting operational evidence detected for '${req.name}'. Auditor review required.`,
        missing_requirements: [],
        warnings: ['Contradictory evidence detected within sub-control']
      };
    }

    // Sub-control PASS
    const bestItem = validatedItems[0];
    return {
      id: req.id,
      name: req.name,
      description: req.description,
      status: 'PASS',
      score_earned: maxScore,
      max_score: maxScore,
      confidence: bestItem.validation.confidence,
      evidence: validatedItems.map(i => i.evidence),
      reason: bestItem.validation.validationReason || `Valid evidence verified for '${req.name}'.`,
      missing_requirements: []
    };
  }

  /**
   * Filters all candidate evidence items for those that match the requirement's
   * specific evidence types, keywords, or ID, preventing cross-contamination.
   */
  private static findMatchingEvidenceForRequirement(
    req: SubControlRequirement,
    allEvidence: EvidenceItem[],
    parentParameter: AuditParameter
  ): EvidenceItem[] {
    const reqIdNorm = (req.id || '').toLowerCase().replace(/[-\s]/g, '_');
    const reqNameNorm = (req.name || req.title || req.id || '').toLowerCase();
    const reqKeywords = (req.keywords || []).map(k => k.toLowerCase());
    const reqEvidenceTypes = (req.evidence_types || []).map(t => t.toLowerCase().replace(/[-\s]/g, '_'));

    return allEvidence.filter(evid => {
      const fnLower = (evid.filename || '').toLowerCase();
      const snipLower = (evid.snippet || '').toLowerCase();
      const rawTextLower = ((evid.extracted_fields?.raw_text || evid.extracted_fields?.text || '') as string).toLowerCase();
      const evidTypeNorm = (evid.evidence_type || '').toLowerCase().replace(/[-\s]/g, '_');
      const evidDomain = evid.document_domain || evid.extracted_fields?.document_domain;

      // 0. Domain Compatibility Check: If requirement specifies domain and evidence has domain, enforce match
      if (req.domain && evidDomain && evidDomain !== 'UNASSIGNED') {
        const domainMatches = assertEvidenceDomainMatchesControl(req.domain, evidDomain, req.allowed_domains);
        if (!domainMatches) {
          return false;
        }
      }

      // 1. Check direct evidence_type match
      if (reqEvidenceTypes.length > 0 && reqEvidenceTypes.includes(evidTypeNorm)) {
        return true;
      }

      // 2. Check sub-control specific keywords
      if (reqKeywords.length > 0) {
        const matchesKw = reqKeywords.some(kw => fnLower.includes(kw) || snipLower.includes(kw) || rawTextLower.includes(kw));
        if (matchesKw) return true;
      }

      // 3. Check requirement ID / name keywords
      if (reqIdNorm && (fnLower.includes(reqIdNorm) || snipLower.includes(reqIdNorm) || rawTextLower.includes(reqIdNorm))) {
        return true;
      }
      if (reqNameNorm && (fnLower.includes(reqNameNorm) || snipLower.includes(reqNameNorm) || rawTextLower.includes(reqNameNorm))) {
        return true;
      }

      // 4. Strict Isolation Check for known isolated types
      // For instance: Fire Drill documents must NOT match Fire Extinguisher requirements!
      if (reqIdNorm.includes('extinguisher') && (evidTypeNorm.includes('drill') || fnLower.includes('drill'))) {
        return false;
      }
      if (reqIdNorm.includes('lease') && (evidTypeNorm.includes('shops') || fnLower.includes('shops') || evidDomain === 'SHOPS_AND_ESTABLISHMENT')) {
        return false;
      }
      if (reqIdNorm.includes('shops') && (evidTypeNorm.includes('lease') || fnLower.includes('lease') || evidDomain === 'RENT_LEASE_AGREEMENT')) {
        return false;
      }
      if (reqIdNorm.includes('power') && !rawTextLower.includes('power') && !rawTextLower.includes('ups') && !rawTextLower.includes('generator') && (evidTypeNorm.includes('antivirus') || fnLower.includes('antivirus'))) {
        return false;
      }
      if (reqIdNorm.includes('internet') && !rawTextLower.includes('internet') && !rawTextLower.includes('isp') && !rawTextLower.includes('failover') && (evidTypeNorm.includes('antivirus') || fnLower.includes('antivirus'))) {
        return false;
      }
      if (reqIdNorm.includes('antivirus') && !rawTextLower.includes('antivirus') && !rawTextLower.includes('edr') && (fnLower.includes('ups') || fnLower.includes('isp'))) {
        return false;
      }

      return false;
    });
  }

  /**
   * Aggregates sub-control results according to logical operator (AND, OR, GROUP)
   */
  private static aggregateResults(
    logic: RequirementLogic,
    parameter: AuditParameter,
    subResults: SubControlResult[],
    maxScore: number
  ): {
    finalStatus: AuditParameterStatus;
    scoreEarned: number;
    reason: string;
    missingRequirements: string[];
    warnings: string[];
  } {
    const passedResults = subResults.filter(r => r.status === 'PASS');
    const reviewResults = subResults.filter(r => r.status === 'REVIEW');
    const failResults = subResults.filter(r => r.status === 'FAIL');
    const notFoundResults = subResults.filter(r => r.status === 'EVIDENCE_NOT_FOUND');

    const totalCount = subResults.length;
    const passedCount = passedResults.length;

    let missingRequirements = subResults
      .filter(r => r.status !== 'PASS')
      .flatMap(r => (r.missing_requirements && r.missing_requirements.length > 0) ? r.missing_requirements : [(r.name || r.title || r.id)]);

    if (missingRequirements.length === 0) {
      missingRequirements = subResults
        .filter(r => r.status !== 'PASS')
        .map(r => `${r.name || r.title || r.id} compliance implementation evidence`);
    }

    const warnings = Array.from(new Set(subResults.flatMap(r => r.warnings || [])));

    let finalStatus: AuditParameterStatus = 'EVIDENCE_NOT_FOUND';
    let scoreEarned = 0;
    let reason = '';

    switch (logic) {
      case 'AND': {
        if (passedCount === totalCount) {
          finalStatus = 'PASS';
          scoreEarned = maxScore;
          reason = `All compound requirements satisfied: ${subResults.map(r => r.name || r.title || r.id).join(', ')}.`;
        } else if (notFoundResults.length === totalCount) {
          finalStatus = 'EVIDENCE_NOT_FOUND';
          scoreEarned = 0;
          reason = `No evidence found for any required sub-controls (${subResults.map(r => r.name || r.title || r.id).join(', ')}).`;
        } else if (failResults.length > 0) {
          // If any sub-control explicitly failed (e.g. expired document), compound is FAIL
          finalStatus = parameter.fatal ? 'FAIL' : (passedCount > 0 ? 'REVIEW' : 'FAIL');
          scoreEarned = Number((maxScore * (passedCount / totalCount)).toFixed(2));
          reason = `Compound requirement failed. Failed sub-control: ${failResults.map(r => r.name || r.title || r.id).join(', ')}. Missing/Incomplete: ${missingRequirements.join(', ')}.`;
        } else {
          // Partial evidence or review needed
          finalStatus = 'REVIEW';
          scoreEarned = Number((maxScore * (passedCount / totalCount)).toFixed(2));
          const satisfiedNames = passedResults.map(r => r.name || r.title || r.id).join(', ');
          reason = `Compound requirement partially satisfied (${passedCount}/${totalCount} verified${satisfiedNames ? ': ' + satisfiedNames : ''}). Incomplete: ${missingRequirements.join(', ')}.`;
        }
        break;
      }

      case 'OR': {
        if (passedCount > 0) {
          finalStatus = 'PASS';
          scoreEarned = maxScore;
          const passedNames = passedResults.map(r => r.name || r.title || r.id).join(', ');
          reason = `Alternative requirement satisfied via: ${passedNames}.`;
        } else if (reviewResults.length > 0) {
          finalStatus = 'REVIEW';
          scoreEarned = 0;
          reason = `Candidate evidence provided for alternative requirements (${reviewResults.map(r => r.name || r.title || r.id).join(', ')}), but requires auditor review.`;
        } else if (notFoundResults.length === totalCount) {
          finalStatus = 'EVIDENCE_NOT_FOUND';
          scoreEarned = 0;
          reason = `No evidence found for any of the alternative options (${subResults.map(r => r.name || r.title || r.id).join(' OR ')}).`;
        } else {
          finalStatus = 'FAIL';
          scoreEarned = 0;
          reason = `None of the alternative options (${subResults.map(r => r.name || r.title || r.id).join(' OR ')}) were satisfied.`;
        }
        break;
      }

      case 'GROUP': {
        if (passedCount === totalCount) {
          finalStatus = 'PASS';
          scoreEarned = maxScore;
          reason = `All grouped operational controls verified (${passedCount}/${totalCount}): ${subResults.map(r => r.name || r.title || r.id).join(', ')}.`;
        } else if (passedCount > 0) {
          finalStatus = 'REVIEW';
          scoreEarned = Number((maxScore * (passedCount / totalCount)).toFixed(2));
          reason = `Grouped controls partially satisfied (${passedCount}/${totalCount} operational). Missing: ${missingRequirements.join(', ')}.`;
        } else if (notFoundResults.length === totalCount) {
          finalStatus = 'EVIDENCE_NOT_FOUND';
          scoreEarned = 0;
          reason = `No evidence found for any grouped operational controls (${subResults.map(r => r.name || r.title || r.id).join(', ')}).`;
        } else {
          finalStatus = 'FAIL';
          scoreEarned = 0;
          reason = `Grouped operational controls failed verification (${passedCount}/${totalCount}). Missing: ${missingRequirements.join(', ')}.`;
        }
        break;
      }

      default: {
        finalStatus = passedCount === totalCount ? 'PASS' : (passedCount > 0 ? 'REVIEW' : 'FAIL');
        scoreEarned = passedCount === totalCount ? maxScore : Number((maxScore * (passedCount / totalCount)).toFixed(2));
        reason = `Evaluated requirements (${passedCount}/${totalCount} satisfied).`;
        break;
      }
    }

    return {
      finalStatus,
      scoreEarned,
      reason,
      missingRequirements,
      warnings
    };
  }

  /**
   * Resolves requirements from parameter either via explicit `requirements`
   * or converts legacy `sub_controls` strings into `SubControlRequirement[]`.
   */
  private static resolveRequirements(parameter: AuditParameter): SubControlRequirement[] {
    if (parameter.requirements && parameter.requirements.length > 0) {
      return parameter.requirements;
    }

    if (parameter.sub_controls && parameter.sub_controls.length > 0) {
      return parameter.sub_controls.map(sub => {
        const subId = sub.toUpperCase().replace(/[-\s]/g, '_');
        const formattedName = sub.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
        return {
          id: subId,
          name: formattedName,
          description: `Evidence demonstrating ${formattedName}`,
          evidence_types: [subId],
          keywords: [sub.replace(/_/g, ' ')]
        };
      });
    }

    return [];
  }
}
