export type AuditParameterStatus = 'PASS' | 'FAIL' | 'REVIEW' | 'NOT_APPLICABLE' | 'EVIDENCE_NOT_FOUND';

export type PolicyImplementationStatus = 'POLICY_EXISTS' | 'IMPLEMENTATION_EVIDENCE' | 'BOTH' | 'POLICY_ONLY' | 'NO_EVIDENCE';

export type PoliceVerificationStatus = 'VERIFIED' | 'APPLIED' | 'MISSING' | 'EXPIRED' | 'UNCLEAR';

export type AuditCategory = 'ZERO_TOLERANCE' | 'GOVERNANCE_COMPLIANCE_INFOSEC' | 'INFRASTRUCTURE_PROCESS_MANAGEMENT';

export type RequirementLogic = 'SINGLE' | 'AND' | 'OR' | 'GROUP';

export interface AuditParameter {
  id: string; // e.g., 'ZTI-001'
  category: AuditCategory;
  category_name: string;
  category_weight: number;
  parameter: string;
  fatal: boolean;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  required_evidence: string[];
  keywords: string[];
  logic: RequirementLogic;
  sub_controls?: string[];
  distinguish_policy?: boolean;
  requires_human_review?: boolean;
  requires_validity_check?: boolean;
  expiry_required?: boolean;
  allow_filename_only?: boolean;
  evaluation_rules: string[];
  enabled: boolean;
}

export interface EvidenceItem {
  evidence_id: string;
  file_id: string;
  filename: string;
  path: string;
  evidence_type: string;
  relevance: number; // 0.0 - 1.0
  extracted_fields: Record<string, any>;
  snippet: string;
  page?: number;
  created_at: string;
  candidate?: boolean;
  satisfies_control?: boolean;
  filename_match?: boolean;
  content_match?: boolean;
  metadata_match?: boolean;
  entity_match?: boolean;
  field_validation?: boolean;
  semantic_match?: boolean;
  is_filename_only?: boolean;
}

export interface AIRecommendation {
  evidence_type: string;
  relevance: number;
  extracted_fields: Record<string, any>;
  reason: string;
  recommended_status: AuditParameterStatus;
  confidence: number;
}

export interface AuditOverride {
  original_status: AuditParameterStatus;
  new_status: AuditParameterStatus;
  auditor_name: string;
  comment: string;
  timestamp: string;
}

export interface AuditParameterResult {
  parameter_id: string;
  parameter: AuditParameter;
  status: AuditParameterStatus;
  confidence: number;
  fatal: boolean;
  score_earned: number;
  max_score: number;
  policy_status?: PolicyImplementationStatus;
  pv_status?: PoliceVerificationStatus;
  sub_control_statuses?: Record<string, AuditParameterStatus>;
  evidence: EvidenceItem[];
  reason: string;
  missing_requirements: string[];
  warnings: string[];
  ai_recommendation?: AIRecommendation;
  override?: AuditOverride;
}

export interface AuditSession {
  audit_id: string;
  audit_date: string;
  agency_name: string;
  auditor_name: string;
  status: 'IN_PROGRESS' | 'COMPLETED' | 'CANCELLED';
  total_parameters: number;
  pass_count: number;
  fail_count: number;
  review_count: number;
  not_found_count: number;
  fatal_failures_count: number;
  overall_score: number;
  max_score: number;
  overall_status: 'COMPLIANT' | 'NON_COMPLIANT' | 'FATAL_FAILURE' | 'NEEDS_REVIEW';
  category_scores: Record<string, { earned: number; max: number; status: string }>;
  created_at: string;
  updated_at: string;
  parameter_results?: AuditParameterResult[];
}

export interface EvidenceGap {
  priority: 'HIGH' | 'MEDIUM' | 'LOW';
  parameter_id: string;
  parameter_title: string;
  category: string;
  fatal: boolean;
  status: AuditParameterStatus;
  missing: string;
  recommended_action: string;
  fatal_impact: boolean;
}

export type AuditGap = EvidenceGap;
