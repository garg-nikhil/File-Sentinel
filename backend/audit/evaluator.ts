import { AuditParameter, AuditParameterResult, EvidenceItem, PolicyImplementationStatus, PoliceVerificationStatus } from './models.js';
import { DateEvaluator } from './dateEvaluator.js';

export class AuditEvaluator {
  /**
   * Evaluates evidence against a parameter to produce a deterministic compliance result
   */
  public evaluateParameter(
    parameter: AuditParameter,
    evidenceItems: EvidenceItem[],
    auditDate: string = new Date().toISOString().split('T')[0]
  ): AuditParameterResult {
    const missingRequirements: string[] = [];
    const warnings: string[] = [];

    // 1. NO EVIDENCE FOUND
    if (evidenceItems.length === 0) {
      return {
        parameter_id: parameter.id,
        parameter,
        status: 'EVIDENCE_NOT_FOUND',
        confidence: 1.0,
        fatal: parameter.fatal,
        score_earned: 0,
        max_score: this.calculateParameterMaxScore(parameter),
        evidence: [],
        reason: `No matching documentary evidence found in scanned files for this requirement.`,
        missing_requirements: [...parameter.required_evidence],
        warnings: ['Evidence missing']
      };
    }

    // 2. FILENAME SPOOFING PROTECTION (FINDING-01)
    // A filename-only match must NEVER satisfy an audit control unless explicitly permitted
    const isFilenameOnlyMatch = evidenceItems.every(e => e.is_filename_only || e.extracted_fields?.is_filename_only);
    if (isFilenameOnlyMatch && !parameter.allow_filename_only) {
      return {
        parameter_id: parameter.id,
        parameter,
        status: 'REVIEW',
        confidence: 0.90,
        fatal: parameter.fatal,
        score_earned: 0,
        max_score: this.calculateParameterMaxScore(parameter),
        evidence: evidenceItems,
        reason: `Candidate evidence discovered based on filename ('${evidenceItems[0].filename}'), but document body content did not match parameter requirements or pass content validation. Filename-only matches cannot satisfy audit controls without validated body content.`,
        missing_requirements: ['Validated document body content'],
        warnings: ['Filename-only match detected (potential filename spoofing)', ...warnings]
      };
    }

    // 3. CHECK ENTITY NAME CORRELATION ACROSS EVIDENCE (FINDING-04)
    const entityNames = evidenceItems
      .map(e => e.extracted_fields?.person_name)
      .filter((n): n is string => Boolean(n));
    if (entityNames.length > 1) {
      const uniqueNames = new Set(entityNames.map(n => n.toLowerCase().trim()));
      if (uniqueNames.size > 1) {
        warnings.push(`POSSIBLE_ENTITY_MISMATCH: Name variance detected across documents (${Array.from(uniqueNames).join(' vs ')})`);
      }
    }

    // 4. HUMAN REVIEW PARAMETERS
    if (parameter.requires_human_review) {
      return {
        parameter_id: parameter.id,
        parameter,
        status: 'REVIEW',
        confidence: 0.85,
        fatal: parameter.fatal,
        score_earned: 0,
        max_score: this.calculateParameterMaxScore(parameter),
        evidence: evidenceItems,
        reason: `Documentary evidence identified (${evidenceItems.length} file(s)), but physical or behavioral compliance requires auditor verification.`,
        missing_requirements: [],
        warnings: ['Requires physical or human auditor verification', ...warnings]
      };
    }

    // 5. POLICY VS IMPLEMENTATION DISTINCTION
    if (parameter.distinguish_policy) {
      const hasPolicyOnly = evidenceItems.every(e => e.extracted_fields?.is_policy && !e.extracted_fields?.is_implementation);
      const hasImplementation = evidenceItems.some(e => e.extracted_fields?.is_implementation);

      let policyStatus: PolicyImplementationStatus = 'NO_EVIDENCE';
      if (hasPolicyOnly) policyStatus = 'POLICY_ONLY';
      else if (hasImplementation && evidenceItems.some(e => e.extracted_fields?.is_policy)) policyStatus = 'BOTH';
      else if (hasImplementation) policyStatus = 'IMPLEMENTATION_EVIDENCE';

      if (hasPolicyOnly) {
        return {
          parameter_id: parameter.id,
          parameter,
          status: 'REVIEW',
          confidence: 0.90,
          fatal: parameter.fatal,
          score_earned: 0,
          max_score: this.calculateParameterMaxScore(parameter),
          policy_status: policyStatus,
          evidence: evidenceItems,
          reason: `Policy document found, but no technical or operational implementation evidence (e.g. system screenshots, GPO/DLP export, audit logs) was found. Policy presence alone cannot establish compliance.`,
          missing_requirements: ['Operational implementation evidence (system config, screenshot, audit dump)'],
          warnings: ['Policy document alone is insufficient to pass', ...warnings]
        };
      }
    }

    // 6. EXPIRY & TIME-BOUND CONTROLS EVALUATION (FINDING-02)
    if (parameter.requires_validity_check || parameter.expiry_required) {
      const expiryDates = evidenceItems
        .map(e => e.extracted_fields?.expiry_date)
        .filter((d): d is string => Boolean(d));

      if (expiryDates.length > 0) {
        const primaryExpiry = expiryDates[0];
        if (DateEvaluator.isExpired(primaryExpiry, auditDate)) {
          return {
            parameter_id: parameter.id,
            parameter,
            status: 'FAIL',
            confidence: 0.98,
            fatal: parameter.fatal,
            score_earned: 0,
            max_score: this.calculateParameterMaxScore(parameter),
            evidence: evidenceItems,
            reason: `Time-bound requirement expired on ${primaryExpiry} relative to audit date ${auditDate}.`,
            missing_requirements: ['Active unexpired document'],
            warnings: ['Document expiry date has passed', ...warnings]
          };
        }
      } else if (parameter.expiry_required) {
        return {
          parameter_id: parameter.id,
          parameter,
          status: 'REVIEW',
          confidence: 0.85,
          fatal: parameter.fatal,
          score_earned: 0,
          max_score: this.calculateParameterMaxScore(parameter),
          evidence: evidenceItems,
          reason: `Expiration date is required for time-bound control '${parameter.parameter}', but no explicit expiry date was extracted from evidence. Auditor review required.`,
          missing_requirements: ['Explicit expiration date on evidence document'],
          warnings: ['Expiry date required but missing from evidence', ...warnings]
        };
      }
    }

    // 7. PARAMETER SPECIFIC EVALUATION RULES

    // ZTI-005 Police Verification
    if (parameter.id === 'ZTI-005') {
      return this.evaluatePoliceVerification(parameter, evidenceItems, auditDate, warnings);
    }

    // IPM-008 Fire Drill (Older than 1 year)
    if (parameter.id === 'IPM-008') {
      const drillDate = evidenceItems[0]?.extracted_fields?.issue_date;
      if (drillDate && DateEvaluator.isOlderThanYears(drillDate, auditDate, 1)) {
        return {
          parameter_id: parameter.id,
          parameter,
          status: 'FAIL',
          confidence: 0.95,
          fatal: parameter.fatal,
          score_earned: 0,
          max_score: this.calculateParameterMaxScore(parameter),
          evidence: evidenceItems,
          reason: `Latest fire drill date (${drillDate}) is older than 1 year relative to audit date (${auditDate}).`,
          missing_requirements: ['Fire drill conducted within the last 12 months'],
          warnings: ['Fire drill date expired', ...warnings]
        };
      }
    }

    // IPM-004 Insurance Expiry
    if (parameter.id === 'IPM-004') {
      const expiryDate = evidenceItems[0]?.extracted_fields?.expiry_date;
      if (expiryDate && DateEvaluator.isExpired(expiryDate, auditDate)) {
        return {
          parameter_id: parameter.id,
          parameter,
          status: 'FAIL',
          confidence: 0.98,
          fatal: parameter.fatal,
          score_earned: 0,
          max_score: this.calculateParameterMaxScore(parameter),
          evidence: evidenceItems,
          reason: `Commercial General Liability insurance policy expired on ${expiryDate} (Audit Date: ${auditDate}).`,
          missing_requirements: ['Valid active insurance policy'],
          warnings: ['Insurance policy expired', ...warnings]
        };
      }
    }

    // COMPOUND / SUB-CONTROL EVALUATION
    if (parameter.logic === 'AND' && parameter.sub_controls) {
      return this.evaluateAndSubControls(parameter, evidenceItems, warnings);
    }

    if (parameter.logic === 'GROUP' && parameter.sub_controls) {
      return this.evaluateGroupSubControls(parameter, evidenceItems, warnings);
    }

    // DEFAULT PASS STATUS
    const maxScore = this.calculateParameterMaxScore(parameter);
    return {
      parameter_id: parameter.id,
      parameter,
      status: 'PASS',
      confidence: 0.95,
      fatal: parameter.fatal,
      score_earned: maxScore,
      max_score: maxScore,
      evidence: evidenceItems,
      reason: `Valid acceptable documentary evidence identified satisfying parameter requirements.`,
      missing_requirements: [],
      warnings
    };
  }

  /**
   * Specific Police Verification (ZTI-005) Evaluator
   */
  private evaluatePoliceVerification(
    parameter: AuditParameter,
    evidenceItems: EvidenceItem[],
    auditDate: string,
    warnings: string[]
  ): AuditParameterResult {
    const combinedText = evidenceItems.map(e => `${e.filename} ${e.snippet}`).join(' ').toLowerCase();

    let pvStatus: PoliceVerificationStatus = 'UNCLEAR';
    let status: 'PASS' | 'FAIL' | 'REVIEW' = 'REVIEW';
    let reason = '';

    if (combinedText.includes('verified') || combinedText.includes('police clearance certificate') || combinedText.includes('clearance report')) {
      pvStatus = 'VERIFIED';
      status = 'PASS';
      reason = 'Valid police verification certificate verified.';
    } else if (combinedText.includes('applied') || combinedText.includes('acknowledgement') || combinedText.includes('receipt')) {
      pvStatus = 'APPLIED';
      status = 'PASS';
      reason = 'Documented proof of Police Verification application identified.';
    } else if (combinedText.includes('expired')) {
      pvStatus = 'EXPIRED';
      status = 'FAIL';
      reason = 'Police verification report has expired.';
    } else if (combinedText.includes('missing') || combinedText.includes('rejected')) {
      pvStatus = 'MISSING';
      status = 'FAIL';
      reason = 'Police verification documentation is missing or rejected.';
    } else {
      pvStatus = 'UNCLEAR';
      status = 'REVIEW';
      reason = 'Police verification evidence found but status is ambiguous. Auditor review required.';
    }

    const maxScore = this.calculateParameterMaxScore(parameter);
    return {
      parameter_id: parameter.id,
      parameter,
      status,
      confidence: 0.92,
      fatal: parameter.fatal,
      score_earned: status === 'PASS' ? maxScore : 0,
      max_score: maxScore,
      pv_status: pvStatus,
      evidence: evidenceItems,
      reason,
      missing_requirements: status === 'FAIL' ? ['Valid PV or proof of application'] : [],
      warnings
    };
  }

  /**
   * Compound AND Sub-Controls Evaluator (e.g. Rent/Lease AND Shops & Establishment, CCTV installed AND 90 days retention)
   */
  private evaluateAndSubControls(
    parameter: AuditParameter,
    evidenceItems: EvidenceItem[],
    warnings: string[]
  ): AuditParameterResult {
    const maxScore = this.calculateParameterMaxScore(parameter);
    const subStatuses: Record<string, 'PASS' | 'FAIL' | 'REVIEW'> = {};
    const combined = evidenceItems.map(e => `${e.filename} ${e.snippet}`).join(' ').toLowerCase();

    const missingSubs: string[] = [];

    for (const sub of parameter.sub_controls || []) {
      const subKey = sub.toLowerCase().replace(/_/g, ' ');
      if (combined.includes(subKey) || combined.includes(subKey.split(' ')[0])) {
        subStatuses[sub] = 'PASS';
      } else {
        subStatuses[sub] = 'FAIL';
        missingSubs.push(sub);
      }
    }

    const allPassed = Object.values(subStatuses).every(s => s === 'PASS');
    const finalStatus = allPassed ? 'PASS' : 'FAIL';

    return {
      parameter_id: parameter.id,
      parameter,
      status: finalStatus,
      confidence: 0.90,
      fatal: parameter.fatal,
      score_earned: finalStatus === 'PASS' ? maxScore : 0,
      max_score: maxScore,
      sub_control_statuses: subStatuses,
      evidence: evidenceItems,
      reason: allPassed
        ? `All compound sub-requirements (${parameter.sub_controls?.join(', ')}) satisfied.`
        : `Compound requirement incomplete. Missing: ${missingSubs.join(', ')}.`,
      missing_requirements: missingSubs,
      warnings
    };
  }

  /**
   * GROUP Sub-Controls Evaluator (e.g., Power Backup / Internet Backup / Antivirus)
   */
  private evaluateGroupSubControls(
    parameter: AuditParameter,
    evidenceItems: EvidenceItem[],
    warnings: string[]
  ): AuditParameterResult {
    const maxScore = this.calculateParameterMaxScore(parameter);
    const subStatuses: Record<string, 'PASS' | 'FAIL' | 'REVIEW'> = {};
    const combined = evidenceItems.map(e => `${e.filename} ${e.snippet}`).join(' ').toLowerCase();

    let passedCount = 0;
    const missingSubs: string[] = [];

    for (const sub of parameter.sub_controls || []) {
      const subKey = sub.toLowerCase().replace(/_/g, ' ');
      if (combined.includes(subKey) || combined.includes(subKey.split(' ')[0])) {
        subStatuses[sub] = 'PASS';
        passedCount++;
      } else {
        subStatuses[sub] = 'FAIL';
        missingSubs.push(sub);
      }
    }

    const totalSubs = parameter.sub_controls?.length || 1;
    const ratio = passedCount / totalSubs;
    const scoreEarned = Math.round(maxScore * ratio);

    let finalStatus: 'PASS' | 'FAIL' | 'REVIEW' = 'PASS';
    if (ratio === 0) finalStatus = 'FAIL';
    else if (ratio < 1) finalStatus = 'REVIEW';

    return {
      parameter_id: parameter.id,
      parameter,
      status: finalStatus,
      confidence: 0.88,
      fatal: parameter.fatal,
      score_earned: scoreEarned,
      max_score: maxScore,
      sub_control_statuses: subStatuses,
      evidence: evidenceItems,
      reason: `Evaluated group controls (${passedCount}/${totalSubs} satisfied). ${missingSubs.length > 0 ? 'Missing: ' + missingSubs.join(', ') : ''}`,
      missing_requirements: missingSubs,
      warnings
    };
  }

  /**
   * Calculates maximum points for a parameter based on category rules
   */
  public calculateParameterMaxScore(parameter: AuditParameter): number {
    if (parameter.category === 'ZERO_TOLERANCE') return 10; // 10 params * 10 = 100
    if (parameter.category === 'GOVERNANCE_COMPLIANCE_INFOSEC') return 7.5; // 8 params * 7.5 = 60
    if (parameter.category === 'INFRASTRUCTURE_PROCESS_MANAGEMENT') return 3.64; // 11 params * ~3.64 = 40
    return 10;
  }
}
