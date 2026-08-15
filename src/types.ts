export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type Category = 'SECRETS' | 'PII' | 'FINANCIAL' | 'SECURITY' | 'DOCUMENT' | 'METADATA';

export type Classification = 'RESTRICTED' | 'CONFIDENTIAL' | 'INTERNAL' | 'PUBLIC' | 'UNKNOWN';

export type FindingSource = 'RULE' | 'HEURISTIC' | 'AI';

export type ScanStatus = 'PENDING' | 'SCANNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED' | 'SCAN_LIMIT_EXCEEDED';

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
  scan_status: 'SUCCESS' | 'ERROR' | 'SKIPPED';
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

export interface AppSettings {
  maxFileSizeMB: number;
  maxScanDepth: number;
  aiEnabled: boolean;
  cloudUploadEnabled: boolean;
  redactSensitivePreview: boolean;
  cloudBucketName: string;
  quarantineLocalDir: string;
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
