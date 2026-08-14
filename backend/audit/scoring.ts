import { AuditParameterResult, AuditSession } from './models.js';

export class AuditScoringEngine {
  /**
   * Computes category scores, fatal flags, and overall audit score & status
   */
  public static calculateAuditSummary(
    auditId: string,
    agencyName: string,
    auditorName: string,
    auditDate: string,
    parameterResults: AuditParameterResult[]
  ): AuditSession {
    let passCount = 0;
    let failCount = 0;
    let reviewCount = 0;
    let notFoundCount = 0;
    let fatalFailuresCount = 0;

    let totalScoreEarned = 0;
    let totalMaxScore = 0;

    const categoryScores: Record<string, { earned: number; max: number; status: string }> = {
      ZERO_TOLERANCE: { earned: 0, max: 100, status: 'PASS' },
      GOVERNANCE_COMPLIANCE_INFOSEC: { earned: 0, max: 60, status: 'PASS' },
      INFRASTRUCTURE_PROCESS_MANAGEMENT: { earned: 0, max: 40, status: 'PASS' }
    };

    for (const res of parameterResults) {
      // Effective status considering auditor overrides
      const effectiveStatus = res.override ? res.override.new_status : res.status;

      if (effectiveStatus === 'PASS') passCount++;
      else if (effectiveStatus === 'FAIL') {
        failCount++;
        if (res.fatal) fatalFailuresCount++;
      } else if (effectiveStatus === 'REVIEW') reviewCount++;
      else if (effectiveStatus === 'EVIDENCE_NOT_FOUND') {
        notFoundCount++;
        if (res.fatal && !res.parameter.requires_human_review) fatalFailuresCount++; // Missing evidence for a fatal parameter is a fatal failure unless marked for on-site human review
      }

      const categoryKey = res.parameter.category;
      if (!categoryScores[categoryKey]) {
        categoryScores[categoryKey] = { earned: 0, max: 0, status: 'PASS' };
      }

      // Add earned points if PASS or overridden to PASS
      const earnedPoints = effectiveStatus === 'PASS' ? res.max_score : res.score_earned;
      categoryScores[categoryKey].earned += earnedPoints;
      categoryScores[categoryKey].max += res.max_score;

      totalScoreEarned += earnedPoints;
      totalMaxScore += res.max_score;
    }

    // Determine category status
    for (const catKey of Object.keys(categoryScores)) {
      const cat = categoryScores[catKey];
      cat.earned = Math.min(cat.max, Number(cat.earned.toFixed(1)));
      if (cat.earned === cat.max) cat.status = 'PASS';
      else if (cat.earned > cat.max * 0.7) cat.status = 'NEEDS_REVIEW';
      else cat.status = 'FAIL';
    }

    totalScoreEarned = Math.min(totalMaxScore, Math.round(totalScoreEarned));

    // Determine Overall Audit Status
    let overallStatus: 'COMPLIANT' | 'NON_COMPLIANT' | 'FATAL_FAILURE' | 'NEEDS_REVIEW' = 'COMPLIANT';

    if (fatalFailuresCount > 0) {
      overallStatus = 'FATAL_FAILURE';
    } else if (failCount > 0) {
      overallStatus = 'NON_COMPLIANT';
    } else if (reviewCount > 0 || notFoundCount > 0) {
      overallStatus = 'NEEDS_REVIEW';
    }

    return {
      audit_id: auditId,
      audit_date: auditDate,
      agency_name: agencyName || 'Primary Telecalling & Collection Agency',
      auditor_name: auditorName || 'System Automated Inspector',
      status: 'COMPLETED',
      total_parameters: parameterResults.length,
      pass_count: passCount,
      fail_count: failCount,
      review_count: reviewCount,
      not_found_count: notFoundCount,
      fatal_failures_count: fatalFailuresCount,
      overall_score: totalScoreEarned,
      max_score: Math.round(totalMaxScore),
      overall_status: overallStatus,
      category_scores: categoryScores,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      parameter_results: parameterResults
    };
  }
}
