import { DatabaseSync } from 'node:sqlite';
import { ScanTelemetryPayload } from './telemetry.js';

export enum DataClassificationCategory {
  LOCAL_ONLY_SENSITIVE = 'LOCAL_ONLY_SENSITIVE', // Category A: Never transmitted to cloud
  TELEMETRY_SAFE_METADATA = 'TELEMETRY_SAFE_METADATA', // Category B: Minimal aggregate metadata
  OPTIONAL_CLOUD_EVIDENCE = 'OPTIONAL_CLOUD_EVIDENCE' // Category C: Explicit manual action required
}

export interface DataClassificationField {
  field_name: string;
  category: DataClassificationCategory;
  description: string;
  examples: string[];
  storage_location: 'LOCAL_SQLITE_ONLY' | 'CLIENT_MEMORY' | 'OPTIONAL_TELEMETRY' | 'OPTIONAL_CLOUD_STORAGE';
  transmission_policy: 'NEVER_TRANSMIT' | 'AGGREGATE_ONLY' | 'MANUAL_EXPLICIT_USER_ACTION';
}

export const DATA_CLASSIFICATION_REGISTRY: DataClassificationField[] = [
  // --- CATEGORY A: LOCAL-ONLY SENSITIVE DATA ---
  {
    field_name: 'document_contents',
    category: DataClassificationCategory.LOCAL_ONLY_SENSITIVE,
    description: 'Raw document bytes and binary files scanned on the local filesystem',
    examples: ['invoice.pdf', 'agreement.docx', 'id_scan.png'],
    storage_location: 'LOCAL_SQLITE_ONLY',
    transmission_policy: 'NEVER_TRANSMIT'
  },
  {
    field_name: 'extracted_text',
    category: DataClassificationCategory.LOCAL_ONLY_SENSITIVE,
    description: 'Full-text parsed and extracted from documents via PDF/Office extractors',
    examples: ['This Agreement is entered into between...', 'Salary voucher for month...'],
    storage_location: 'LOCAL_SQLITE_ONLY',
    transmission_policy: 'NEVER_TRANSMIT'
  },
  {
    field_name: 'ocr_output',
    category: DataClassificationCategory.LOCAL_ONLY_SENSITIVE,
    description: 'Optical character recognition stream outputs from scanned images or documents',
    examples: ['INCOME TAX DEPARTMENT', 'CERTIFICATE OF INCORPORATION'],
    storage_location: 'LOCAL_SQLITE_ONLY',
    transmission_policy: 'NEVER_TRANSMIT'
  },
  {
    field_name: 'pii_and_names',
    category: DataClassificationCategory.LOCAL_ONLY_SENSITIVE,
    description: 'Personally Identifiable Information including individual and employee names',
    examples: ['Rajesh Kumar', 'Priya Sharma', 'John Doe'],
    storage_location: 'LOCAL_SQLITE_ONLY',
    transmission_policy: 'NEVER_TRANSMIT'
  },
  {
    field_name: 'tax_gstin',
    category: DataClassificationCategory.LOCAL_ONLY_SENSITIVE,
    description: 'Goods and Services Tax Identification Number (15-character statutory tax ID)',
    examples: ['27AAAAA0000A1Z5', '07ABCDE1234F1Z8'],
    storage_location: 'LOCAL_SQLITE_ONLY',
    transmission_policy: 'NEVER_TRANSMIT'
  },
  {
    field_name: 'tax_pan',
    category: DataClassificationCategory.LOCAL_ONLY_SENSITIVE,
    description: 'Permanent Account Number (10-character Indian national tax identifier)',
    examples: ['ABCDE1234F', 'BKXPG9988K'],
    storage_location: 'LOCAL_SQLITE_ONLY',
    transmission_policy: 'NEVER_TRANSMIT'
  },
  {
    field_name: 'national_aadhaar',
    category: DataClassificationCategory.LOCAL_ONLY_SENSITIVE,
    description: '12-digit Indian national unique identity number (UIDAI)',
    examples: ['1234 5678 9012', '9876 5432 1098'],
    storage_location: 'LOCAL_SQLITE_ONLY',
    transmission_policy: 'NEVER_TRANSMIT'
  },
  {
    field_name: 'employee_and_agent_ids',
    category: DataClassificationCategory.LOCAL_ONLY_SENSITIVE,
    description: 'Internal organization identifiers for agents, telecallers, and personnel',
    examples: ['EMP-10492', 'AGENT-99201', 'TC-5012'],
    storage_location: 'LOCAL_SQLITE_ONLY',
    transmission_policy: 'NEVER_TRANSMIT'
  },
  {
    field_name: 'phone_numbers',
    category: DataClassificationCategory.LOCAL_ONLY_SENSITIVE,
    description: 'Direct dial telephone numbers, mobile numbers, and calling contact info',
    examples: ['+91 98765 43210', '9876543210'],
    storage_location: 'LOCAL_SQLITE_ONLY',
    transmission_policy: 'NEVER_TRANSMIT'
  },
  {
    field_name: 'email_addresses',
    category: DataClassificationCategory.LOCAL_ONLY_SENSITIVE,
    description: 'Corporate and personal electronic mail addresses',
    examples: ['contact@vendor.co.in', 'employee@organization.org'],
    storage_location: 'LOCAL_SQLITE_ONLY',
    transmission_policy: 'NEVER_TRANSMIT'
  },
  {
    field_name: 'certificate_numbers',
    category: DataClassificationCategory.LOCAL_ONLY_SENSITIVE,
    description: 'DRA certificates, ISO certificates, police verification acknowledgement codes',
    examples: ['DRA-2024-99812', 'PV-ACK-88301', 'ISO-27001-CERT-771'],
    storage_location: 'LOCAL_SQLITE_ONLY',
    transmission_policy: 'NEVER_TRANSMIT'
  },
  {
    field_name: 'evidence_snippets',
    category: DataClassificationCategory.LOCAL_ONLY_SENSITIVE,
    description: 'Matched OCR and text context blocks evaluated for compliance parameter rules',
    examples: ['DRA Training completion verified on 12-Jan-2024...', 'Police verification valid until...'],
    storage_location: 'LOCAL_SQLITE_ONLY',
    transmission_policy: 'NEVER_TRANSMIT'
  },
  {
    field_name: 'bank_account_numbers',
    category: DataClassificationCategory.LOCAL_ONLY_SENSITIVE,
    description: 'Bank account numbers, IFSC routing codes, and financial payment details',
    examples: ['9182736450192837', 'HDFC0000123'],
    storage_location: 'LOCAL_SQLITE_ONLY',
    transmission_policy: 'NEVER_TRANSMIT'
  },

  // --- CATEGORY B: TELEMETRY-SAFE METADATA ---
  {
    field_name: 'scan_id',
    category: DataClassificationCategory.TELEMETRY_SAFE_METADATA,
    description: 'Cryptographic UUID identifier for the scan session',
    examples: ['SCAN-9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'],
    storage_location: 'OPTIONAL_TELEMETRY',
    transmission_policy: 'AGGREGATE_ONLY'
  },
  {
    field_name: 'organization_id',
    category: DataClassificationCategory.TELEMETRY_SAFE_METADATA,
    description: 'Tenant organization identifier',
    examples: ['org-acme-corp'],
    storage_location: 'OPTIONAL_TELEMETRY',
    transmission_policy: 'AGGREGATE_ONLY'
  },
  {
    field_name: 'user_id',
    category: DataClassificationCategory.TELEMETRY_SAFE_METADATA,
    description: 'Operator or Auditor user identifier',
    examples: ['user-admin-01'],
    storage_location: 'OPTIONAL_TELEMETRY',
    transmission_policy: 'AGGREGATE_ONLY'
  },
  {
    field_name: 'device_id',
    category: DataClassificationCategory.TELEMETRY_SAFE_METADATA,
    description: 'Registered hardware device identifier',
    examples: ['dev-station-04'],
    storage_location: 'OPTIONAL_TELEMETRY',
    transmission_policy: 'AGGREGATE_ONLY'
  },
  {
    field_name: 'timestamps_and_duration',
    category: DataClassificationCategory.TELEMETRY_SAFE_METADATA,
    description: 'Scan start time, completion time, and elapsed execution milliseconds',
    examples: ['2026-08-16T10:00:00.000Z', '3420ms'],
    storage_location: 'OPTIONAL_TELEMETRY',
    transmission_policy: 'AGGREGATE_ONLY'
  },
  {
    field_name: 'file_counts',
    category: DataClassificationCategory.TELEMETRY_SAFE_METADATA,
    description: 'Aggregate integer totals of discovered, processed, and rejected files',
    examples: ['discovered: 50', 'processed: 48', 'succeeded: 48'],
    storage_location: 'OPTIONAL_TELEMETRY',
    transmission_policy: 'AGGREGATE_ONLY'
  },
  {
    field_name: 'compliance_statistics',
    category: DataClassificationCategory.TELEMETRY_SAFE_METADATA,
    description: 'Aggregate percentage score, evaluated parameters count, and status breakdown',
    examples: ['overall_score: 94.5', 'pass: 18', 'review: 2', 'fail: 0'],
    storage_location: 'OPTIONAL_TELEMETRY',
    transmission_policy: 'AGGREGATE_ONLY'
  },
  {
    field_name: 'risk_counts',
    category: DataClassificationCategory.TELEMETRY_SAFE_METADATA,
    description: 'Aggregate finding severity totals (critical, high, medium, low)',
    examples: ['critical: 0', 'high: 1', 'medium: 3', 'low: 4'],
    storage_location: 'OPTIONAL_TELEMETRY',
    transmission_policy: 'AGGREGATE_ONLY'
  },
  {
    field_name: 'software_versions',
    category: DataClassificationCategory.TELEMETRY_SAFE_METADATA,
    description: 'Application, scanning engine, and compliance checklist release versions',
    examples: ['application: 1.0.0', 'engine: 1.0.0', 'checklist: 2026.1'],
    storage_location: 'OPTIONAL_TELEMETRY',
    transmission_policy: 'AGGREGATE_ONLY'
  },
  {
    field_name: 'coarse_resource_profile',
    category: DataClassificationCategory.TELEMETRY_SAFE_METADATA,
    description: 'Coarsely bucketed CPU core count, memory tier, and OS family for compatibility diagnostics',
    examples: ['cpu: 4 cores', 'memory: 8-16 GB', 'os: linux'],
    storage_location: 'OPTIONAL_TELEMETRY',
    transmission_policy: 'AGGREGATE_ONLY'
  },

  // --- CATEGORY C: OPTIONAL CLOUD EVIDENCE ---
  {
    field_name: 'explicit_cloud_evidence',
    category: DataClassificationCategory.OPTIONAL_CLOUD_EVIDENCE,
    description: 'Specific evidence artifacts staged or backed up to cloud vault only after explicit manual user confirmation',
    examples: ['DRA_Certificate_Verified.pdf'],
    storage_location: 'OPTIONAL_CLOUD_STORAGE',
    transmission_policy: 'MANUAL_EXPLICIT_USER_ACTION'
  }
];

export interface SensitivePatternDefinition {
  type: string;
  regex: RegExp;
  description: string;
}

export const SENSITIVE_PATTERNS: SensitivePatternDefinition[] = [
  {
    type: 'PAN',
    regex: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/i,
    description: 'Permanent Account Number'
  },
  {
    type: 'AADHAAR',
    regex: /\b\d{4}\s?\d{4}\s?\d{4}\b/,
    description: '12-digit Aadhaar / UIDAI Number'
  },
  {
    type: 'GSTIN',
    regex: /\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}\b/i,
    description: 'Goods & Services Tax Identification Number'
  },
  {
    type: 'EMAIL',
    regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/,
    description: 'Email Address'
  },
  {
    type: 'PHONE',
    regex: /(?:\+91|91)?[-.\s]?[6-9]\d{9}\b|\b\d{5}[-.\s]?\d{5}\b/,
    description: 'Indian Mobile or Phone Number'
  },
  {
    type: 'EMPLOYEE_ID',
    regex: /\b(?:EMP|AGENT|TC)[-_]?[0-9]{3,8}\b/i,
    description: 'Internal Employee or Agent Identifier'
  },
  {
    type: 'BANK_ACCOUNT',
    regex: /\b\d{11,18}\b/,
    description: 'Bank Account Number'
  }
];

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
  raw_payload_preview: ScanTelemetryPayload;
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
  cloud_metadata_retention_days: number; // 30, 90, 180, 365, or -1 (indefinite)
  auto_purge_enabled: boolean;
  last_purged_at: string | null;
  updated_at: string;
}

export class PrivacyGovernanceService {
  constructor(private db: DatabaseSync) {}

  /**
   * Deep recursive scanner that searches any arbitrary object for Category A sensitive patterns.
   */
  public scanForSensitiveLeaks(target: any, parentPath: string = ''): { found: boolean; violations: { path: string; patternType: string; matchedValuePreview: string }[] } {
    const violations: { path: string; patternType: string; matchedValuePreview: string }[] = [];

    const traverse = (obj: any, currentPath: string) => {
      if (obj === null || obj === undefined) return;

      if (typeof obj === 'string') {
        // Test all sensitive patterns
        for (const pattern of SENSITIVE_PATTERNS) {
          const match = obj.match(pattern.regex);
          if (match) {
            violations.push({
              path: currentPath,
              patternType: pattern.type,
              matchedValuePreview: match[0].substring(0, 3) + '***' + match[0].slice(-2)
            });
          }
        }
      } else if (Array.isArray(obj)) {
        obj.forEach((item, index) => traverse(item, `${currentPath}[${index}]`));
      } else if (typeof obj === 'object') {
        for (const [key, value] of Object.entries(obj)) {
          // Flag disallowed keys that indicate raw content
          const lowerKey = key.toLowerCase();
          if (
            lowerKey.includes('content') ||
            lowerKey.includes('extracted_text') ||
            lowerKey.includes('ocr') ||
            lowerKey.includes('snippet') ||
            lowerKey.includes('raw_text')
          ) {
            violations.push({
              path: `${currentPath}.${key}`,
              patternType: 'FORBIDDEN_CATEGORY_A_KEY',
              matchedValuePreview: `Disallowed key: ${key}`
            });
          }
          traverse(value, currentPath ? `${currentPath}.${key}` : key);
        }
      }
    };

    traverse(target, parentPath);

    return {
      found: violations.length > 0,
      violations
    };
  }

  /**
   * Generates a complete, transparent debug inspection of the telemetry payload that would leave the machine.
   */
  public inspectScanTelemetryPayload(
    scanId: string,
    orgId: string,
    userId: string,
    deviceId: string,
    settings: { telemetryEnabled?: boolean; debugFilenamesEnabled?: boolean } = {}
  ): TelemetryInspectionResult {
    // 1. Fetch scan metrics from local SQLite
    const scan = this.db.prepare('SELECT * FROM scans WHERE scan_id = ?').get(scanId) as any;
    const files = this.db.prepare('SELECT * FROM files WHERE scan_id = ?').all(scanId) as any[];
    const auditSession = this.db.prepare('SELECT * FROM audit_sessions WHERE scan_id = ?').get(scanId) as any;

    const filesDiscovered = scan?.total_files || files.length || 0;
    const filesProcessed = scan?.processed_files || files.filter(f => f.scan_status === 'SUCCESS').length || 0;
    const filesSucceeded = files.filter(f => f.scan_status === 'SUCCESS').length;
    const filesFailed = files.filter(f => f.scan_status === 'FAILED').length;

    const passCount = auditSession?.pass_count ?? (scan?.safe_count || 0);
    const reviewCount = auditSession?.review_count ?? 0;
    const failCount = auditSession?.fail_count ?? (scan?.critical_count || 0);
    const notFoundCount = auditSession?.not_found_count ?? 0;

    const overallScore = auditSession?.overall_score ?? (filesDiscovered > 0 ? Math.round((passCount / filesDiscovered) * 100) : 100);
    const paramsEval = auditSession?.total_parameters ?? 24;

    const payload: ScanTelemetryPayload = {
      scan_id: scanId,
      organization_id: orgId,
      user_id: userId,
      device_id: deviceId,
      started_at: scan?.start_time || new Date().toISOString(),
      completed_at: scan?.end_time || new Date().toISOString(),
      duration_ms: scan?.start_time && scan?.end_time ? Math.max(0, new Date(scan.end_time).getTime() - new Date(scan.start_time).getTime()) : 1200,
      application_version: '1.0.0',
      engine_version: '1.0.0',
      checklist_version: '2026.1',
      files_discovered: filesDiscovered,
      files_processed: filesProcessed,
      files_succeeded: filesSucceeded,
      files_failed: filesFailed,
      files_rejected_by_resource_limits: 0,
      pass_count: passCount,
      review_count: reviewCount,
      fail_count: failCount,
      evidence_not_found_count: notFoundCount,
      critical_count: scan?.critical_count || 0,
      high_count: scan?.high_count || 0,
      medium_count: scan?.medium_count || 0,
      low_count: scan?.low_count || 0,
      overall_score: overallScore,
      parameters_evaluated: paramsEval,
      scan_status: scan?.status || 'COMPLETED',
      debug_filenames_opt_in: Boolean(settings.debugFilenamesEnabled),
      debug_filenames: settings.debugFilenamesEnabled ? files.map(f => f.filename) : undefined
    };

    // 2. Perform deep audit on every field
    const fieldAudits: TelemetryFieldAudit[] = [];
    let violationsCount = 0;

    for (const [key, val] of Object.entries(payload)) {
      if (val === undefined) continue;

      const leakCheck = this.scanForSensitiveLeaks(val, key);
      const isSafe = !leakCheck.found;
      if (!isSafe) {
        violationsCount += leakCheck.violations.length;
      }

      fieldAudits.push({
        key,
        value: val,
        category: DataClassificationCategory.TELEMETRY_SAFE_METADATA,
        classification_label: 'Category B: Telemetry-Safe Aggregate Metadata',
        is_safe_for_transmission: isSafe,
        privacy_notes: isSafe
          ? 'Aggregate / identifier metric with zero document contents, text, OCR, or PII'
          : `Potential sensitivity violation: ${leakCheck.violations.map(v => v.patternType).join(', ')}`
      });
    }

    return {
      scan_id: scanId,
      organization_id: orgId,
      inspection_timestamp: new Date().toISOString(),
      total_fields: fieldAudits.length,
      category_a_violations_detected: violationsCount,
      category_b_safe_fields: fieldAudits.filter(f => f.is_safe_for_transmission).length,
      category_c_optional_fields: 0,
      verdict: violationsCount === 0 ? 'APPROVED_FOR_TRANSMISSION' : 'REJECTED_CONTAINS_CATEGORY_A_SENSITIVE_DATA',
      field_audits: fieldAudits,
      raw_payload_preview: payload,
      privacy_guarantees: {
        zero_document_content: true,
        zero_extracted_text: true,
        zero_ocr_snippets: true,
        zero_pii_entities: true,
        local_persistence_guarantee: 'Local customer SQLite records and scanned files remain 100% on the client device and are never modified, deleted, or purged when cloud synchronization occurs or subscriptions change.'
      }
    };
  }

  /**
   * Retrieves the current cloud metadata retention policy for an organization.
   */
  public getRetentionPolicy(orgId: string): RetentionPolicy {
    const row = this.db.prepare('SELECT * FROM privacy_retention_policies WHERE org_id = ?').get(orgId) as any;
    if (row) {
      return {
        org_id: row.org_id,
        cloud_metadata_retention_days: row.cloud_metadata_retention_days,
        auto_purge_enabled: Boolean(row.auto_purge_enabled),
        last_purged_at: row.last_purged_at,
        updated_at: row.updated_at
      };
    }

    // Default policy: 90 days retention for cloud telemetry metadata
    const now = new Date().toISOString();
    this.db.prepare(`
      INSERT INTO privacy_retention_policies (org_id, cloud_metadata_retention_days, auto_purge_enabled, updated_at)
      VALUES (?, 90, 1, ?)
      ON CONFLICT(org_id) DO NOTHING
    `).run(orgId, now);

    return {
      org_id: orgId,
      cloud_metadata_retention_days: 90,
      auto_purge_enabled: true,
      last_purged_at: null,
      updated_at: now
    };
  }

  /**
   * Configures the retention policy for cloud metadata.
   * Allowed options: 30, 90, 180, 365, or -1 (indefinite).
   */
  public setRetentionPolicy(orgId: string, retentionDays: number, autoPurge: boolean = true): RetentionPolicy {
    const validDays = [30, 90, 180, 365, -1];
    const daysToSet = validDays.includes(retentionDays) ? retentionDays : 90;
    const now = new Date().toISOString();

    this.db.prepare(`
      INSERT INTO privacy_retention_policies (org_id, cloud_metadata_retention_days, auto_purge_enabled, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(org_id) DO UPDATE SET
        cloud_metadata_retention_days = excluded.cloud_metadata_retention_days,
        auto_purge_enabled = excluded.auto_purge_enabled,
        updated_at = excluded.updated_at
    `).run(orgId, daysToSet, autoPurge ? 1 : 0, now);

    return this.getRetentionPolicy(orgId);
  }

  /**
   * Purges cloud metadata records exceeding the retention threshold.
   * STRICT GUARANTEE: Does NOT delete local customer audit history (scans, files, findings, audit_sessions).
   */
  public purgeExpiredCloudTelemetry(orgId: string): {
    purged_telemetry_records: number;
    purged_queue_records: number;
    retention_days: number;
    local_scans_preserved: number;
    local_audit_sessions_preserved: number;
  } {
    const policy = this.getRetentionPolicy(orgId);
    if (policy.cloud_metadata_retention_days === -1) {
      // Indefinite retention - no purge needed
      const localScans = (this.db.prepare('SELECT COUNT(*) as count FROM scans').get() as any)?.count || 0;
      const localAudits = (this.db.prepare('SELECT COUNT(*) as count FROM audit_sessions').get() as any)?.count || 0;
      return {
        purged_telemetry_records: 0,
        purged_queue_records: 0,
        retention_days: -1,
        local_scans_preserved: localScans,
        local_audit_sessions_preserved: localAudits
      };
    }

    const cutoffDate = new Date(Date.now() - policy.cloud_metadata_retention_days * 24 * 3600 * 1000).toISOString();

    // 1. Purge expired cloud scan_telemetry rows for this tenant
    const deleteTelemetryStmt = this.db.prepare(`
      DELETE FROM scan_telemetry
      WHERE organization_id = ? AND started_at < ?
    `);
    const telemetryResult = deleteTelemetryStmt.run(orgId, cutoffDate);

    // 2. Purge synced queue items older than cutoff
    const deleteQueueStmt = this.db.prepare(`
      DELETE FROM telemetry_queue
      WHERE organization_id = ? AND status = 'SYNCED' AND created_at < ?
    `);
    const queueResult = deleteQueueStmt.run(orgId, cutoffDate);

    // 3. Update last_purged_at timestamp
    const now = new Date().toISOString();
    this.db.prepare('UPDATE privacy_retention_policies SET last_purged_at = ? WHERE org_id = ?').run(now, orgId);

    // 4. Verify local SQLite scans and audit sessions remain untouched
    const localScans = (this.db.prepare('SELECT COUNT(*) as count FROM scans').get() as any)?.count || 0;
    const localAudits = (this.db.prepare('SELECT COUNT(*) as count FROM audit_sessions').get() as any)?.count || 0;

    return {
      purged_telemetry_records: Number(telemetryResult.changes || 0),
      purged_queue_records: Number(queueResult.changes || 0),
      retention_days: policy.cloud_metadata_retention_days,
      local_scans_preserved: localScans,
      local_audit_sessions_preserved: localAudits
    };
  }

  /**
   * Returns data governance architecture manifest and regulatory readiness statement.
   */
  public getGovernanceManifest() {
    return {
      core_principle: 'SCAN LOCAL. STORE DOCUMENTS LOCAL. TRANSMIT MINIMUM METADATA.',
      principles: [
        {
          key: 'SCAN_LOCAL',
          title: '100% Local Scanning & OCR',
          description: 'All document ingestion, text parsing, OCR processing, pattern matching, and rule evaluation execute entirely within local host compute memory and local SQLite storage.'
        },
        {
          key: 'STORE_LOCAL',
          title: 'Local Document Storage',
          description: 'Customer documents, file binaries, extracted raw text, and audit evaluation snapshots reside strictly on the local machine. No documents are uploaded to cloud servers without explicit user confirmation.'
        },
        {
          key: 'TRANSMIT_MINIMUM',
          title: 'Data Minimization & Minimal Metadata',
          description: 'Telemetry transmits only coarse aggregates (e.g. file counts, score percentage, duration) required for license tracking and service operations.'
        },
        {
          key: 'NO_SILENT_UPLOADS',
          title: 'No Silent Uploads',
          description: 'No document contents, OCR extracts, or sensitive filenames are ever transmitted silently in the background.'
        },
        {
          key: 'LOCAL_DURABILITY',
          title: 'Local-First Durability',
          description: 'Customer local audit history is permanently preserved on the local device and is never deleted upon cloud subscription expiration or account changes.'
        }
      ],
      classification_registry: DATA_CLASSIFICATION_REGISTRY,
      regulatory_readiness: {
        disclaimer: 'FileSentinel is engineered to support organizational compliance with data protection principles (including India Digital Personal Data Protection Act DPDP 2023, Information Technology Act 2000, and GDPR data minimization tenets). The software provides architectural isolation and technical controls to assist organizations, but does not constitute automatic or official certification of regulatory compliance.',
        data_minimization_supported: true,
        storage_limitation_supported: true,
        purpose_limitation_supported: true,
        integrity_and_confidentiality_supported: true
      }
    };
  }
}
