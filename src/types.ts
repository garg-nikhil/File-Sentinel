export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type Category = 'SECRETS' | 'PII' | 'FINANCIAL' | 'SECURITY' | 'DOCUMENT' | 'METADATA';

export type Classification = 'RESTRICTED' | 'CONFIDENTIAL' | 'INTERNAL' | 'PUBLIC' | 'UNKNOWN';

export type FindingSource = 'RULE' | 'HEURISTIC' | 'AI';

export type ScanStatus = 'PENDING' | 'SCANNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED' | 'SCAN_LIMIT_EXCEEDED' | 'PAUSED';

export interface Rule {
  id: string;
  name: string;
  category: Category;
  severity: Severity;
  enabled: boolean;
  pattern: string;
  description: string;
  recommendation: string;
  isBuiltIn?: boolean;
}

export interface FindingEvidence {
  snippet?: string;
  line?: number;
  match?: string;
  details?: Record<string, any>;
}

export interface Finding {
  finding_id: string;
  file_id: string;
  rule_id: string;
  severity: Severity;
  category: Category;
  title: string;
  description: string;
  evidence: FindingEvidence;
  confidence: number;
  source: FindingSource;
  recommendation: string;
  created_at: string;
}

export interface FileItem {
  file_id: string;
  scan_id: string;
  path: string;
  filename: string;
  extension: string;
  size: number;
  sha256: string;
  risk_score: number;
  classification: Classification;
  scan_status: 'SUCCESS' | 'ERROR' | 'SKIPPED' | 'PENDING' | 'PROCESSING';
  created_at: string;
  modified_at: string;
  findings_count?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  findings?: Finding[];
  metadata?: Record<string, any>;
  extracted_text_preview?: string;
  warnings?: string[];
  ai_summary?: AISummary;
}

export interface ScanSession {
  scan_id: string;
  root_path: string;
  start_time: string;
  end_time?: string;
  status: ScanStatus;
  total_files: number;
  supported_files: number;
  processed_files: number;
  error_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  safe_count: number;
  current_file?: string;
}

export interface QuarantineItem {
  id: string;
  file_id: string;
  original_path: string;
  filename: string;
  sha256: string;
  size: number;
  cloud_object?: string;
  upload_status: 'PENDING' | 'UPLOADING' | 'UPLOADED' | 'FAILED' | 'NONE';
  verification_status: 'PENDING' | 'VERIFIED' | 'FAILED' | 'NONE';
  deletion_status: 'NOT_DELETED' | 'DELETED' | 'FAILED';
  quarantined_at: string;
  verified_at?: string;
  deleted_at?: string;
  logs: string[];
}

export interface AISummary {
  classification: Classification;
  risk_level: Severity;
  confidence: number;
  categories: Category[];
  summary: string;
  reasoning: string;
  recommended_action: string;
  analyzed_at: string;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  action: string;
  file_path?: string;
  sha256?: string;
  user?: string;
  status: 'SUCCESS' | 'WARNING' | 'ERROR';
  details?: string;
}

export interface RecurringScanConfig {
  enabled: boolean;
  frequency: 'DAILY' | 'WEEKLY' | 'MONTHLY';
  time: string; // e.g. "02:00"
  dayOfWeek: number; // 1 = Mon ... 7 = Sun
  dayOfMonth: number; // 1 .. 31
  targetPaths: string[];
  scanTypes: ('SECURITY' | 'SECRETS' | 'PII' | 'DOCUMENT')[];
  autoQuarantineCritical?: boolean;
  notifyOnCompletion?: boolean;
  notificationEmail?: string;
  generateReportOnComplete?: boolean;
  lastRunTime?: string;
  nextRunTime?: string;
  lastRunStatus?: 'SUCCESS' | 'WARNING' | 'FAILED' | 'NONE';
  lastRunFilesCount?: number;
  lastRunFindingsCount?: number;
}

export interface AppSettings {
  maxFileSizeMB: number;
  maxScanDepth: number;
  aiEnabled: boolean;
  aiPrivacyMode?: 'OFF' | 'REDACTED_SNIPPETS' | 'FULL_TEXT';
  cloudUploadEnabled: boolean;
  telemetryEnabled?: boolean;
  crashReportingEnabled?: boolean;
  debugFilenamesEnabled?: boolean;
  redactSensitivePreview: boolean;
  cloudBucketName: string;
  quarantineLocalDir: string;
  theme?: 'midnight-emerald' | 'cyber-neon' | 'warm-executive' | 'clean-light';
  recurringScan?: RecurringScanConfig;
}

export interface DeviceTelemetryInfo {
  device_id: string;
  os_family: string;
  os_version: string;
  architecture: string;
  filesentinel_version: string;
  coarse_resource_profile?: {
    cpu_cores_bucket: string;
    memory_gb_bucket: string;
  };
}

export interface ScanTelemetryRecord {
  scan_id: string;
  organization_id: string;
  user_id: string;
  device_id: string;
  started_at: string;
  completed_at: string;
  duration_ms: number;
  application_version: string;
  engine_version: string;
  checklist_version: string;
  files_discovered: number;
  files_processed: number;
  files_succeeded: number;
  files_failed: number;
  files_rejected_by_resource_limits: number;
  pass_count: number;
  review_count: number;
  fail_count: number;
  evidence_not_found_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  overall_score: number;
  parameters_evaluated: number;
  scan_status: string;
  device_telemetry?: DeviceTelemetryInfo;
  debug_filenames_opt_in?: boolean;
  debug_filenames?: string[];
  created_at?: string;
  ip_address?: string;
}

export interface DashboardStats {
  totalScans: number;
  totalFilesScanned: number;
  riskBreakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    safe: number;
  };
  classificationBreakdown: Record<Classification, number>;
  extensionBreakdown: Record<string, number>;
  quarantinedCount: number;
  recentScans: ScanSession[];
  highestRiskFiles: FileItem[];
  recentFindings: Finding[];
}

export type LicenseStatus = 'TRIAL' | 'ACTIVE' | 'PAST_DUE' | 'GRACE_PERIOD' | 'SUSPENDED' | 'EXPIRED' | 'CANCELLED';
export type LicenseUIState = 'ACTIVE' | 'TRIAL' | 'EXPIRING_SOON' | 'OFFLINE_GRACE' | 'EXPIRED' | 'DEVICE_LIMIT_REACHED' | 'SCAN_LIMIT_REACHED' | 'SUSPENDED' | 'CANCELLED' | 'NO_LICENSE';

export interface LicenseInfo {
  valid: boolean;
  ui_state: LicenseUIState;
  status: LicenseStatus;
  license_id?: string;
  organization_id?: string;
  plan_id?: string;
  plan_name?: string;
  issued_at?: string;
  starts_at?: string;
  expires_at?: string;
  grace_until?: string | null;
  days_remaining?: number;
  devices_active?: number;
  max_devices?: number;
  scans_used?: number;
  scan_limit?: number;
  feature_flags?: string[];
  grace_active?: boolean;
  error?: string;
}

export interface LicenseDevice {
  id: string;
  license_id: string;
  device_id: string;
  device_name?: string;
  activated_at: string;
  status: 'ACTIVE' | 'DEACTIVATED';
  last_seen_at: string;
  revoked?: number;
}

export interface LicenseAuditEvent {
  id: string;
  license_id: string;
  org_id: string;
  event_type: string;
  timestamp: string;
  details?: Record<string, any>;
  actor_id?: string;
}

export interface CloudDashboardOverview {
  total_scans: number;
  current_score: number;
  previous_score: number;
  score_change: number;
  last_scan: string | null;
  last_scan_id?: string;
  files_scanned: number;
  pass_count: number;
  review_count: number;
  fail_count: number;
  evidence_not_found_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  latest_breakdown?: {
    pass_count: number;
    review_count: number;
    fail_count: number;
    evidence_not_found_count: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
  };
}

export interface ComplianceTrendPoint {
  scan_id: string;
  date: string;
  score: number;
  files: number;
  pass: number;
  review: number;
  fail: number;
  critical: number;
  high: number;
}

export interface CloudManagedDevice {
  device_id: string;
  device_name: string;
  org_id: string;
  revoked: boolean;
  registered_at: string;
  os: string;
  application_version: string;
  last_seen: string;
  license_status: string;
}

export interface CloudManagedUser {
  user_id: string;
  org_id: string;
  username: string;
  role: 'ORG_ADMIN' | 'AUDITOR' | 'OPERATOR' | 'VIEWER';
  disabled: number;
  created_at: string;
}

export interface CloudOrgInfo {
  organization_id: string;
  organization_name: string;
  created_at: string;
  plan: string;
  license_status: string;
  ui_state: string;
  license_valid: boolean;
  expires_at?: string;
  grace_until?: string | null;
  usage: {
    users: { current: number; max: number };
    devices: { current: number; total_registered: number; max: number };
    scans: { used: number; limit: number };
  };
}

export interface CloudSoftwareVersion {
  current_version: string;
  latest_version: string;
  checklist_version: string;
  update_available: boolean;
  channel: string;
  engine: string;
  release_date: string;
}

export interface ReportVerificationResult {
  verified?: boolean;
  status: 'VALID' | 'INVALID' | 'REVOKED';
  match_status?: string;
  message?: string;
  report_id?: string;
  scan_id?: string;
  organization_id?: string;
  user_id?: string;
  device_id?: string;
  completed_at?: string;
  audit_date?: string;
  generated_at?: string;
  report_hash?: string;
  computed_hash?: string;
  hash_matched?: boolean;
  revoked_at?: string | null;
  revocation_reason?: string | null;
  overall_score?: number;
  overall_status?: string;
  scan_status?: string;
  files_processed?: number;
  pass_count?: number;
  review_count?: number;
  fail_count?: number;
  evidence_not_found_count?: number;
  fatal_failures_count?: number;
  critical_count?: number;
  high_count?: number;
  agency_name?: string;
  auditor_name?: string;
  application_version?: string;
  engine_version?: string;
  checklist_version?: string;
  metrics?: {
    overall_score: number;
    max_score: number;
    overall_status: string;
    total_parameters: number;
    pass_count: number;
    fail_count: number;
    review_count: number;
    fatal_failures_count: number;
    agency_name?: string;
    auditor_name?: string;
  };
}

export interface StoredAuditReportItem {
  report_id: string;
  scan_id: string;
  organization_id: string;
  engine_version: string;
  checklist_version: string;
  generated_at: string;
  report_hash: string;
  status: 'VALID' | 'REVOKED' | 'INVALID';
  revoked_at?: string | null;
  revocation_reason?: string | null;
  created_at: string;
}

export interface BillingPlanInfo {
  key: string;
  plan_id: string;
  name: string;
  pricing: {
    monthly_inr: number;
    annual_inr: number;
    currency: string;
    trial_days: number;
  };
  max_users: number;
  max_devices: number;
  scan_limit: number;
  feature_flags: string[];
}

export interface BillingPaymentRecord {
  payment_id: string;
  amount_formatted: string;
  currency: string;
  status: string;
  processed_at: string;
}

export interface OrganizationBillingState {
  organization_id: string;
  customer_id?: string;
  customer_email?: string;
  subscription: {
    subscription_id: string;
    plan_id: string;
    plan_name: string;
    billing_interval: 'MONTHLY' | 'ANNUAL';
    status: 'TRIAL' | 'ACTIVE' | 'PAST_DUE' | 'GRACE_PERIOD' | 'EXPIRED' | 'CANCELLED';
    current_period_start: string;
    current_period_end: string;
    grace_until?: string | null;
    trial_ends_at?: string | null;
    cancel_at_period_end: boolean;
  } | null;
  license_ui_state: string;
  license_status: string;
  license_valid: boolean;
  days_remaining?: number;
  available_plans: BillingPlanInfo[];
  recent_payments: BillingPaymentRecord[];
}

export enum DataClassificationCategory {
  LOCAL_ONLY_SENSITIVE = 'LOCAL_ONLY_SENSITIVE',
  TELEMETRY_SAFE_METADATA = 'TELEMETRY_SAFE_METADATA',
  OPTIONAL_CLOUD_EVIDENCE = 'OPTIONAL_CLOUD_EVIDENCE'
}

export interface DataClassificationField {
  field_name: string;
  category: DataClassificationCategory;
  description: string;
  examples: string[];
  storage_location: 'LOCAL_SQLITE_ONLY' | 'CLIENT_MEMORY' | 'OPTIONAL_TELEMETRY' | 'OPTIONAL_CLOUD_STORAGE';
  transmission_policy: 'NEVER_TRANSMIT' | 'AGGREGATE_ONLY' | 'MANUAL_EXPLICIT_USER_ACTION';
}

export interface GovernanceManifest {
  core_principle: string;
  principles: {
    key: string;
    title: string;
    description: string;
  }[];
  classification_registry: DataClassificationField[];
  regulatory_readiness: {
    disclaimer: string;
    data_minimization_supported: boolean;
    storage_limitation_supported: boolean;
    purpose_limitation_supported: boolean;
    integrity_and_confidentiality_supported: boolean;
  };
}

export interface TelemetryFieldAudit {
  key: string;
  value: any;
  category: DataClassificationCategory;
  classification_label: string;
  is_safe_for_transmission: boolean;
  privacy_notes: string;
}

export interface TelemetryInspectionResult {
  scan_id: string;
  organization_id: string;
  inspection_timestamp: string;
  total_fields: number;
  category_a_violations_detected: number;
  category_b_safe_fields: number;
  category_c_optional_fields: number;
  verdict: 'APPROVED_FOR_TRANSMISSION' | 'REJECTED_CONTAINS_CATEGORY_A_SENSITIVE_DATA';
  field_audits: TelemetryFieldAudit[];
  raw_payload_preview: any;
  privacy_guarantees: {
    zero_document_content: boolean;
    zero_extracted_text: boolean;
    zero_ocr_snippets: boolean;
    zero_pii_entities: boolean;
    local_persistence_guarantee: string;
  };
}

export interface RetentionPolicy {
  org_id: string;
  cloud_metadata_retention_days: number;
  auto_purge_enabled: boolean;
  last_purged_at: string | null;
  updated_at: string;
}

// --- Endpoint Compliance Types (Phase A) ---

export type EndpointPlatform = 'windows' | 'linux' | 'darwin' | 'unsupported';

export type DeviceType =
  | 'WINDOWS_ENDPOINT'
  | 'LINUX_ENDPOINT'
  | 'MACOS_ENDPOINT'
  | 'ANDROID_DEVICE'
  | 'IOS_DEVICE'
  | 'SERVER'
  | 'CLOUD_SERVER'
  | 'UNKNOWN';

export type RuntimeType =
  | 'LOCAL_WINDOWS_AGENT'
  | 'LOCAL_LINUX_AGENT'
  | 'LOCAL_MACOS_AGENT'
  | 'ANDROID_AGENT'
  | 'IOS_AGENT'
  | 'REMOTE_AGENT'
  | 'CLOUD_SERVER'
  | 'UNKNOWN';

export type DetectionSource =
  | 'LOCAL_MACHINE'
  | 'REMOTE_AGENT'
  | 'CLOUD_SERVER'
  | 'UNKNOWN';

export interface AssessmentProvenance {
  endpointId: string;
  assessmentId: string;
  deviceType: DeviceType;
  hostname: string;
  platform: string;
  architecture: string;
  runtimeType: RuntimeType;
  detectionSource: DetectionSource;
  machineUuid: string;
  agentVersion: string;
  applicationVersion: string;
  startedAt: string;
  completedAt: string;
  osVersion?: string;
  runtimeVersion?: string;
  scannerVersion?: string;
}

export type DetectionCategory =
  | 'USB_STORAGE'
  | 'SOCIAL_MEDIA'
  | 'PERSONAL_EMAIL'
  | 'MESSAGING'
  | 'CLOUD_STORAGE';

export type WebAccessCategory =
  | 'SOCIAL_MEDIA'
  | 'PERSONAL_EMAIL'
  | 'MESSAGING'
  | 'CLOUD_STORAGE';

export type USBStatus =
  | 'ENABLED'
  | 'DISABLED'
  | 'UNKNOWN'
  | 'NOT_PRESENT'
  | 'UNSUPPORTED_PLATFORM'
  | 'REQUIRES_ELEVATION';

export type WebAccessStatus =
  | 'ACCESSIBLE'
  | 'BLOCKED'
  | 'INDETERMINATE'
  | 'UNREACHABLE'
  | 'UNSUPPORTED';

export type ConfidenceLevel = 'HIGH' | 'MEDIUM' | 'LOW';

export type DetectionMethod =
  | 'WINDOWS_REGISTRY_QUERY'
  | 'WINDOWS_WMI_QUERY'
  | 'WINDOWS_POWERSHELL'
  | 'HTTPS_PROBE'
  | 'DNS_TCP_PROBE'
  | 'UNSUPPORTED_PLATFORM'
  | 'ELEVATION_REQUIRED'
  | 'MOCK_WINDOWS_SYSTEM';

export type AssessmentOverallStatus =
  | 'COMPLIANT'
  | 'NON_COMPLIANT'
  | 'ATTENTION_REQUIRED'
  | 'INDETERMINATE';

export interface USBStorageDevice {
  device_type: string;
  manufacturer: string;
  model: string;
  device_id?: string;
  connection_status: 'Connected' | 'Disconnected';
}

export interface USBDetectionResult {
  category: 'USB_STORAGE';
  status: USBStatus;
  connectedStorageDevices: USBStorageDevice[];
  connectedDeviceCount: number;
  detectionMethod: DetectionMethod;
  confidence: ConfidenceLevel;
  timestamp: string;
  platform: string;
  endpointId?: string;
  assessmentId?: string;
  detectionSource?: DetectionSource;
  runtimeType?: RuntimeType;
  provenance?: AssessmentProvenance;
  policyDetails?: {
    usbstorServiceStart?: number;
    storageDevicePolicies?: string;
    writeProtect?: boolean;
    denyAll?: boolean;
  };
  errorMessage?: string;
}

export type USBDetectorResult = USBDetectionResult;

export interface WebAccessTarget {
  id: string;
  category: WebAccessCategory;
  service_name: string;
  primary_domain: string;
  probe_url: string;
  expected_identifiers: string[];
}

export interface WebTargetResult {
  category: WebAccessCategory;
  service: string;
  target_domain: string;
  status: WebAccessStatus;
  confidence: ConfidenceLevel;
  detectionMethod: DetectionMethod;
  httpStatusCode?: number;
  reason?: string;
  responseTimeMs?: number;
  timestamp: string;
  endpointId?: string;
  assessmentId?: string;
  detectionSource?: DetectionSource;
  runtimeType?: RuntimeType;
  provenance?: AssessmentProvenance;
}

export interface CategorySummary {
  total: number;
  accessible: number;
  blocked: number;
  indeterminate: number;
  enabled?: boolean;
}

export interface EndpointAssessment {
  id: string;
  assessment_id?: string;
  endpoint_id: string;
  org_id: string;
  device_id: string;
  user_id: string;
  timestamp: string;
  started_at: string;
  completed_at: string;
  platform: string;
  device_type: DeviceType;
  runtime_type: RuntimeType;
  detection_source: DetectionSource;
  hostname: string;
  machine_uuid: string;
  application_version: string;
  agent_version: string;
  overall_status: AssessmentOverallStatus;
  evidence_hash: string;
  provenance: AssessmentProvenance;
  usb_result: USBDetectionResult;
  web_results: WebTargetResult[];
  category_summaries: Record<DetectionCategory, CategorySummary>;
  evidence_text: string;
  created_at: string;
}

export interface EndpointRecord {
  endpoint_id: string;
  org_id: string;
  device_id: string;
  hostname: string;
  platform: string;
  device_type: DeviceType;
  runtime_type: RuntimeType;
  detection_source: DetectionSource;
  machine_uuid: string;
  last_assessment_id?: string;
  last_status?: AssessmentOverallStatus;
  first_seen_at: string;
  last_seen_at: string;
  ip_address?: string;
  metadata?: string;
}

export type ToastType = 'success' | 'violation' | 'warning' | 'info';

export interface ToastNotification {
  id: string;
  title: string;
  message: string;
  type: ToastType;
  timestamp: string;
  scanId?: string;
  fileId?: string;
  filePath?: string;
  read?: boolean;
  actionLabel?: string;
  onAction?: () => void;
  duration?: number;
}




