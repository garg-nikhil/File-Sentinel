export type AuditParameterStatus = 'PASS' | 'FAIL' | 'REVIEW' | 'NOT_APPLICABLE' | 'EVIDENCE_NOT_FOUND';

export type PolicyImplementationStatus = 'POLICY_EXISTS' | 'IMPLEMENTATION_EVIDENCE' | 'BOTH' | 'POLICY_ONLY' | 'NO_EVIDENCE';

export type PoliceVerificationStatus = 'VERIFIED' | 'APPLIED' | 'MISSING' | 'EXPIRED' | 'UNCLEAR';

export type AuditCategory = 'ZERO_TOLERANCE' | 'GOVERNANCE_COMPLIANCE_INFOSEC' | 'INFRASTRUCTURE_PROCESS_MANAGEMENT';

export type RequirementLogic = 'SINGLE' | 'AND' | 'OR' | 'GROUP';

export type EvidenceSourceType =
  | 'DOCUMENT_EVIDENCE'
  | 'TEST_METADATA'
  | 'APPLICATION_METADATA'
  | 'SYSTEM_METADATA'
  | 'UNKNOWN';

export type EvidenceDomain =
  | 'GST_REGISTRATION'
  | 'BIOMETRIC_ACCESS_CONTROL'
  | 'WORKSPACE_SEGREGATION'
  | 'DRA_CERTIFICATION'
  | 'POLICE_VERIFICATION'
  | 'CODE_OF_CONDUCT_DISCIPLINARY'
  | 'AGENT_ONBOARDING'
  | 'ENDPOINT_DATA_RESTRICTION'
  | 'ENDPOINT_SECURITY_POLICY'
  | 'ENDPOINT_DATA_RESTRICTION_CONFIG'
  | 'WEB_COMMUNICATION_FILTERING'
  | 'WEB_FILTERING_POLICY'
  | 'WEB_COMMUNICATION_FILTERING_CONFIG'
  | 'CLEAN_DESK'
  | 'AGENCY_ID_CARD'
  | 'OFFBOARDING_DEACTIVATION'
  | 'STAFF_ATTIRE'
  | 'REFRESHER_TRAINING'
  | 'PERFORMANCE_NDC'
  | 'SCREEN_CAPTURE_RESTRICTION'
  | 'PASSWORD_POLICY'
  | 'OS_PATCH_MANAGEMENT'
  | 'PF_ESIC_PRINCIPAL_EMPLOYER'
  | 'PF_ESIC_REGISTRATION'
  | 'PRINCIPAL_EMPLOYER_CERTIFICATE'
  | 'HR_POSH_POLICY'
  | 'PREMISES_AND_ESTABLISHMENT'
  | 'RENT_LEASE_AGREEMENT'
  | 'SHOPS_ESTABLISHMENT_CERTIFICATE'
  | 'COMMERCIAL_GENERAL_LIABILITY_INSURANCE'
  | 'VISITOR_REGISTER'
  | 'CCTV_SURVEILLANCE_RETENTION'
  | 'CCTV_INSTALLATION'
  | 'CCTV_RETENTION_CONFIG'
  | 'FIRE_EXTINGUISHER_SAFETY'
  | 'FIRE_DRILL_RECENCY'
  | 'INFRASTRUCTURE_REDUNDANCY_EDR'
  | 'POWER_BACKUP'
  | 'INTERNET_BACKUP'
  | 'ANTIVIRUS_EDR'
  | 'BUSINESS_CONTINUITY_PLAN'
  | 'ESCALATION_MATRIX'
  | 'UNASSIGNED'
  | 'TEST_METADATA_DOMAIN';

export type DateSemanticType =
  | 'ISSUE_DATE'
  | 'EFFECTIVE_DATE'
  | 'EXPIRY_DATE'
  | 'REVIEW_DATE'
  | 'APPLICATION_DATE'
  | 'RENEWAL_DATE'
  | 'AUDIT_DATE'
  | 'UNKNOWN_DATE';

export interface ExtractedDateItem {
  value: string; // ISO format YYYY-MM-DD
  type: DateSemanticType;
  sourceText: string;
  context?: string;
  confidence?: number;
  classification?: 'VALIDATED' | 'PARTIALLY_VALIDATED' | 'REVIEW' | 'CONTRADICTORY' | 'NOT_RELEVANT';
}

export interface SubControlRequirement {
  id: string; // e.g., 'RENT_LEASE_AGREEMENT', 'SHOPS_ESTABLISHMENT_CERTIFICATE'
  title?: string;
  name?: string;
  description?: string;
  domain?: EvidenceDomain;
  allowed_domains?: EvidenceDomain[];
  evidence_types?: string[];
  evidenceTypes?: string[];
  keywords?: string[];
  required_evidence?: string[];
  distinguish_policy?: boolean;
  requires_implementation?: boolean;
  requires_human_review?: boolean;
  requires_validity_check?: boolean;
  expiry_required?: boolean;
  validity_type?: 'EXPIRY' | 'RECENCY';
  max_age_days?: number;
  logic?: RequirementLogic;
  sub_requirements?: SubControlRequirement[];
  requirements?: SubControlRequirement[];
}

export interface SubControlResult {
  id: string;
  title?: string;
  name?: string;
  description?: string;
  domain?: EvidenceDomain;
  document_domain?: EvidenceDomain;
  domain_match?: boolean;
  status: AuditParameterStatus;
  evidence: EvidenceItem[];
  evidence_set?: ControlEvidenceSet;
  evidence_types?: string[];
  reason?: string;
  missing_requirements?: string[];
  warnings?: string[];
  policy_status?: PolicyImplementationStatus;
  logic?: RequirementLogic;
  children?: SubControlResult[];
  sub_results?: SubControlResult[];
  confidence?: number;
  classification?: 'VALIDATED' | 'PARTIALLY_VALIDATED' | 'REVIEW' | 'CONTRADICTORY' | 'NOT_RELEVANT';
  score_earned?: number;
  max_score?: number;
}

export interface AuditParameter {
  id: string; // e.g., 'ZTI-001'
  category: AuditCategory;
  category_name: string;
  category_weight: number;
  parameter: string;
  domain?: EvidenceDomain;
  allowed_domains?: EvidenceDomain[];
  fatal: boolean;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  required_evidence: string[];
  keywords: string[];
  logic: RequirementLogic;
  sub_controls?: string[];
  requirements?: SubControlRequirement[];
  sub_requirements?: SubControlRequirement[];
  distinguish_policy?: boolean;
  requires_human_review?: boolean;
  requires_validity_check?: boolean;
  expiry_required?: boolean;
  validity_type?: 'EXPIRY' | 'RECENCY';
  requirement_type?: 'EXPIRY' | 'RECENCY';
  max_age_days?: number;
  allow_filename_only?: boolean;
  allow_keyword_only?: boolean;
  evidence_types?: string[];
  evaluation_rules: string[];
  enabled: boolean;
}

export type EvidenceRole =
  | 'PRIMARY_IMPLEMENTATION'
  | 'SUPPORTING_IMPLEMENTATION'
  | 'ALTERNATIVE_EVIDENCE'
  | 'GOVERNANCE_POLICY'
  | 'DUPLICATE_OR_PARALLEL_EVIDENCE'
  | 'IRRELEVANT_REJECTED';

export interface EvidenceItem {
  evidence_id?: string;
  file_id: string;
  filename: string;
  path?: string;
  evidence_type: string;
  relevance?: number; // 0.0 - 1.0
  extracted_fields?: Record<string, any>;
  snippet?: string;
  page?: number;
  created_at?: string;
  source_type?: EvidenceSourceType;
  sourceType?: EvidenceSourceType;
  control_id?: string;
  control_domain?: EvidenceDomain;
  controlDomain?: EvidenceDomain;
  document_domain?: EvidenceDomain;
  documentDomain?: EvidenceDomain;
  domain?: EvidenceDomain | string;
  domain_match?: boolean;
  domainMatch?: boolean;
  structured_fields?: Record<string, any>;
  validation_status?: 'PASS' | 'REVIEW' | 'FAIL' | 'VALIDATED' | 'FILENAME_ONLY' | 'REJECTED' | 'REJECTED_DOMAIN_MISMATCH' | string;
  validation_reason?: string;
  validationReason?: string;
  candidate?: boolean;
  satisfies_control?: boolean;
  filename_match?: boolean;
  content_match?: boolean;
  metadata_match?: boolean;
  entity_match?: boolean;
  field_validation?: boolean;
  semantic_match?: boolean;
  is_filename_only?: boolean;
  is_content_only?: boolean;
  // CamelCase property aliases
  filenameMatch?: boolean;
  contentMatch?: boolean;
  metadataMatch?: boolean;
  entityMatch?: boolean;
  fieldValidation?: boolean;
  semanticMatch?: boolean;
  isFilenameOnly?: boolean;
  isContentOnly?: boolean;
  validated?: boolean;
  is_valid?: boolean;
  isValid?: boolean;
  semantic_intent?: string;
  semanticIntent?: string;
  text_preview?: string;
  textPreview?: string;
  mandatory_fields_present?: string[];
  mandatoryFieldsPresent?: string[];
  satisfiesControl?: boolean;
  confidence?: number;
  classification?: 'VALIDATED' | 'PARTIALLY_VALIDATED' | 'REVIEW' | 'CONTRADICTORY' | 'NOT_RELEVANT';
  evidenceRole?: EvidenceRole;
  evidenceQualityScore?: number;
  domainMatchScore?: number;
  structuredFieldScore?: number;
  implementationScore?: number;
  entityCorrelationScore?: number;
  semanticDateScore?: number;
  finalCandidateScore?: number;
  sha256?: string;
  isDuplicateHash?: boolean;
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
  parentParameterId?: string;
  parameter: AuditParameter;
  status: AuditParameterStatus;
  finalStatus?: AuditParameterStatus;
  logic?: RequirementLogic;
  confidence: number;
  fatal: boolean;
  score_earned: number;
  max_score: number;
  policy_status?: PolicyImplementationStatus;
  pv_status?: PoliceVerificationStatus;
  sub_control_statuses?: Record<string, AuditParameterStatus>;
  sub_control_results?: SubControlResult[];
  children?: SubControlResult[];
  evidence: EvidenceItem[];
  evidence_set?: ControlEvidenceSet;
  reason: string;
  missing_requirements: string[];
  warnings: string[];
  ai_recommendation?: AIRecommendation;
  override?: AuditOverride;
}

export interface EntityEvidenceReference {
  parameterId: string;
  parameterTitle?: string;
  fileId: string;
  filename: string;
  evidenceId?: string;
  confidence?: number;
  classification?: 'VALIDATED' | 'PARTIALLY_VALIDATED' | 'REVIEW' | 'CONTRADICTORY' | 'NOT_RELEVANT';
  extractedName?: string;
  extractedAgentId?: string;
  extractedEmployeeId?: string;
  extractedCertNumber?: string;
  extractedFields?: Record<string, any>;
  // Snake_case aliases
  parameter_id?: string;
  parameter_title?: string;
  file_id?: string;
  evidence_id?: string;
  extracted_name?: string;
  extracted_agent_id?: string;
  extracted_employee_id?: string;
  extracted_cert_number?: string;
  extracted_fields?: Record<string, any>;
}

export interface EntityConflict {
  conflictType: 'AGENT_ID_NAME_MISMATCH' | 'EMPLOYEE_ID_NAME_MISMATCH' | 'CERTIFICATE_NUMBER_MISMATCH' | 'IDENTITY_ATTRIBUTE_CONFLICT' | 'POSSIBLE_ENTITY_MISMATCH';
  severity: 'REVIEW' | 'WARNING';
  title: string;
  description: string;
  reason: string;
  involvedEvidence: EntityEvidenceReference[];
  conflictingAttributes: {
    attribute: string;
    values: string[];
  };
  // Snake_case aliases
  conflict_type?: string;
  involved_evidence?: EntityEvidenceReference[];
  conflicting_attributes?: {
    attribute: string;
    values: string[];
  };
}

export interface AuditEntity {
  entityId: string;
  entityType: 'PERSON' | 'ORGANIZATION' | 'AGENCY';
  displayName: string;
  normalizedName: string;
  identifiers: {
    employeeId: string | null;
    agentId: string | null;
    certificateNumber: string | null;
    email: string | null;
    phone: string | null;
    agencyId?: string | null;
    // Snake_case aliases
    employee_id?: string | null;
    agent_id?: string | null;
    certificate_number?: string | null;
    agency_id?: string | null;
  };
  evidenceReferences: EntityEvidenceReference[];
  matchingSignals: string[];
  confidence: number;
  status: 'CONSISTENT' | 'REVIEW';
  conflicts: EntityConflict[];
  auditSessionId?: string;
  createdAt: string;
  // Snake_case aliases
  entity_id?: string;
  entity_type?: 'PERSON' | 'ORGANIZATION' | 'AGENCY';
  display_name?: string;
  normalized_name?: string;
  evidence_references?: EntityEvidenceReference[];
  matching_signals?: string[];
  audit_session_id?: string;
  created_at?: string;
}

export interface AuditEntityFinding {
  findingId: string;
  entityId: string;
  title: string;
  status: 'REVIEW';
  reason: string;
  conflictingAttributes: Record<string, string[]>;
  evidenceReferences: EntityEvidenceReference[];
  createdAt: string;
  // Snake_case aliases
  finding_id?: string;
  entity_id?: string;
  conflicting_attributes?: Record<string, string[]>;
  evidence_references?: EntityEvidenceReference[];
  created_at?: string;
}

export interface AuditSessionEntityResolutionResult {
  entities: AuditEntity[];
  conflicts: EntityConflict[];
  entityFindings: AuditEntityFinding[];
  summary: {
    totalEntities: number;
    consistentCount: number;
    reviewCount: number;
    // Snake_case aliases
    total_entities?: number;
    consistent_count?: number;
    review_count?: number;
  };
  // Snake_case aliases
  entity_findings?: AuditEntityFinding[];
}

export interface AuditSession {
  audit_id: string;
  scan_id?: string;
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
  entities?: AuditEntity[];
  entity_conflicts?: EntityConflict[];
  entity_findings?: AuditEntityFinding[];
  entity_resolution?: AuditSessionEntityResolutionResult;
  // CamelCase aliases
  entityConflicts?: EntityConflict[];
  entityFindings?: AuditEntityFinding[];
  entityResolution?: AuditSessionEntityResolutionResult;
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

export interface ControlEvidenceSet {
  controlId: string;
  primaryEvidence: EvidenceItem | null;
  supportingEvidence: EvidenceItem[];
  reviewEvidence: EvidenceItem[];
  contradictoryEvidence: EvidenceItem[];
  rejectedCandidates: EvidenceItem[];
}
