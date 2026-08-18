/**
 * FILE-SENTINEL — Phase A & B: Endpoint Compliance Detection & Provenance Engine
 * Central Coordinator & Tenant-Scoped Compliance Engine
 *
 * STRICTLY DETECTION ONLY:
 * - NO remediation or system state modification
 * - Pure discovery, classification, reporting, and evidence generation
 * - Deterministic server-side Assessment Provenance & Endpoint Identity
 */

import os from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import { execSync } from 'node:child_process';
import fs from 'node:fs';
import { getDatabase } from '../db.js';
import {
  EndpointAssessment,
  EndpointDetectorOptions,
  DetectionCategory,
  CategorySummary,
  AssessmentOverallStatus,
  WebTargetResult,
  USBDetectionResult,
  EndpointRuntimeProvider,
  EndpointPlatform,
  AssessmentProvenance,
  DeviceType,
  RuntimeType,
  DetectionSource
} from './endpointTypes.js';
import { USBDetector, USBDetectorConfig } from './usbDetector.js';
import { WebAccessDetector, WebAccessDetectorOptions } from './webAccessDetector.js';
import { EndpointEvidenceGenerator } from './endpointEvidence.js';

export const APPLICATION_VERSION = '8.2.0-PhaseA';
export const AGENT_VERSION = '1.0.0';

function detectHostPlatform(): EndpointPlatform {
  const current = os.platform();
  if (current === 'win32') return 'windows';
  if (current === 'linux') return 'linux';
  if (current === 'darwin') return 'darwin';
  return 'unsupported';
}

const currentHostPlatform = detectHostPlatform();

export const LOCAL_WINDOWS_AGENT_RUNTIME: EndpointRuntimeProvider = {
  type: 'LOCAL_WINDOWS_AGENT',
  platform: currentHostPlatform,
  isLocalExecution: true,
  runtimeDescription: `Local FileSentinel agent runtime running directly on the monitored ${currentHostPlatform} endpoint machine.`
};

/**
 * Deterministic helper to get machine UUID without throwing
 */
export function getMachineUuid(): string {
  try {
    const plat = os.platform();
    if (plat === 'linux') {
      if (fs.existsSync('/etc/machine-id')) {
        const id = fs.readFileSync('/etc/machine-id', 'utf8').trim();
        if (id) return id;
      }
      if (fs.existsSync('/var/lib/dbus/machine-id')) {
        const id = fs.readFileSync('/var/lib/dbus/machine-id', 'utf8').trim();
        if (id) return id;
      }
    } else if (plat === 'win32') {
      try {
        const stdout = execSync('reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid', { timeout: 1500, stdio: ['ignore', 'pipe', 'ignore'] }).toString();
        const match = stdout.match(/MachineGuid\s+REG_SZ\s+([a-fA-F0-9\-]+)/i);
        if (match && match[1]) return match[1].trim();
      } catch {}
    } else if (plat === 'darwin') {
      try {
        const stdout = execSync('ioreg -rd1 -c IOPlatformExpertDevice', { timeout: 1500, stdio: ['ignore', 'pipe', 'ignore'] }).toString();
        const match = stdout.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/i);
        if (match && match[1]) return match[1].trim();
      } catch {}
    }
  } catch {}
  return 'UNKNOWN';
}

/**
 * Generate standardized Endpoint ID: FS-EP-XXXXXXXX (8 uppercase hex)
 */
export function generateEndpointId(seed?: string): string {
  if (seed) {
    const hash = crypto.createHash('sha256').update(seed, 'utf8').digest('hex');
    return `FS-EP-${hash.substring(0, 8).toUpperCase()}`;
  }
  return `FS-EP-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
}

/**
 * Generate standardized Assessment ID: EP-ASM-YYYYMMDD-XXXXXX
 */
export function generateAssessmentId(date?: Date): string {
  const d = date || new Date();
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, '0');
  const day = String(d.getUTCDate()).padStart(2, '0');
  const rand = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `EP-ASM-${y}${m}${day}-${rand}`;
}

export class EndpointComplianceEngine {
  private db: DatabaseSync;
  private usbDetector: USBDetector;
  private webDetector: WebAccessDetector;
  private options: EndpointDetectorOptions;
  private runtimeProvider: EndpointRuntimeProvider;

  constructor(db?: DatabaseSync, options: EndpointDetectorOptions = {}) {
    this.db = db || getDatabase();
    this.options = options;

    const usbConfig: USBDetectorConfig = {
      platformOverride: options.platformOverride,
      mockResult: options.mockWindowsUsbData
    };
    this.usbDetector = new USBDetector(usbConfig);

    const detectedPlatform = this.usbDetector.getPlatform();
    this.runtimeProvider = {
      type: detectedPlatform === 'windows' ? 'LOCAL_WINDOWS_AGENT' : detectedPlatform === 'linux' ? 'LOCAL_LINUX_AGENT' : detectedPlatform === 'darwin' ? 'LOCAL_MACOS_AGENT' : 'UNKNOWN',
      platform: detectedPlatform,
      isLocalExecution: true,
      runtimeDescription: `Local FileSentinel agent runtime running directly on the monitored ${detectedPlatform} endpoint machine.`
    };

    const webConfig: WebAccessDetectorOptions = {
      targets: options.customWebTargets,
      connectionTimeoutMs: options.connectionTimeoutMs,
      requestTimeoutMs: options.requestTimeoutMs,
      maxResponseSizeBytes: options.maxResponseSizeBytes,
      maxRedirects: options.maxRedirects,
      concurrencyLimit: options.concurrencyLimit
    };
    this.webDetector = new WebAccessDetector(webConfig);
  }

  public getRuntimeProvider(): EndpointRuntimeProvider {
    return this.runtimeProvider;
  }

  public getUsbDetector(): USBDetector {
    return this.usbDetector;
  }

  public getWebDetector(): WebAccessDetector {
    return this.webDetector;
  }

  /**
   * Get or register a stable endpoint identifier for a device within a tenant
   */
  public getOrCreateEndpoint(orgId: string, deviceId: string, details?: {
    hostname?: string;
    platform?: string;
    architecture?: string;
    deviceType?: DeviceType;
    runtimeType?: RuntimeType;
    machineUuid?: string;
  }): { endpointId: string; deviceType: DeviceType; runtimeType: RuntimeType; hostname: string } {
    const existing = this.db.prepare(
      'SELECT endpoint_id, device_type, runtime_type, hostname FROM endpoints WHERE org_id = ? AND device_id = ?'
    ).get(orgId, deviceId) as { endpoint_id: string; device_type: string; runtime_type: string; hostname: string } | undefined;

    const now = new Date().toISOString();
    const hostname = details?.hostname || os.hostname() || 'UNKNOWN';
    const plat = details?.platform || this.usbDetector.getPlatform();
    const arch = details?.architecture || os.arch();
    const deviceType: DeviceType = details?.deviceType || (plat === 'windows' ? 'WINDOWS_ENDPOINT' : plat === 'linux' ? 'LINUX_ENDPOINT' : plat === 'darwin' ? 'MACOS_ENDPOINT' : 'UNKNOWN');
    const runtimeType: RuntimeType = details?.runtimeType || (plat === 'windows' ? 'LOCAL_WINDOWS_AGENT' : plat === 'linux' ? 'LOCAL_LINUX_AGENT' : plat === 'darwin' ? 'LOCAL_MACOS_AGENT' : 'UNKNOWN');
    const machineUuid = details?.machineUuid || getMachineUuid();

    if (existing) {
      this.db.prepare(
        'UPDATE endpoints SET last_seen_at = ?, hostname = ?, status = ? WHERE endpoint_id = ? AND org_id = ?'
      ).run(now, hostname, 'ACTIVE', existing.endpoint_id, orgId);

      return {
        endpointId: existing.endpoint_id,
        deviceType: (existing.device_type as DeviceType) || deviceType,
        runtimeType: (existing.runtime_type as RuntimeType) || runtimeType,
        hostname: existing.hostname || hostname
      };
    }

    const endpointId = generateEndpointId(`${orgId}:${deviceId}`);

    this.db.prepare(`
      INSERT INTO endpoints (
        endpoint_id, org_id, device_id, hostname, machine_uuid, device_type, platform, architecture, runtime_type, created_at, last_seen_at, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
    `).run(endpointId, orgId, deviceId, hostname, machineUuid, deviceType, plat, arch, runtimeType, now, now);

    return { endpointId, deviceType, runtimeType, hostname };
  }

  /**
   * Calculate deterministic SHA-256 evidence hash for assessment data
   */
  public calculateEvidenceHash(params: {
    assessmentId: string;
    endpointId: string;
    orgId: string;
    deviceId: string;
    timestamp: string;
    detectionSource: DetectionSource;
    runtimeType: RuntimeType;
    usbResult: USBDetectionResult;
    webResults: WebTargetResult[];
  }): string {
    const canonicalWeb = params.webResults.map(w => ({
      category: w.category,
      confidence: w.confidence,
      detectionMethod: w.detectionMethod,
      service: w.service,
      status: w.status,
      target_domain: w.target_domain
    })).sort((a, b) => a.service.localeCompare(b.service));

    const canonicalData = {
      assessmentId: params.assessmentId,
      detectionSource: params.detectionSource,
      deviceId: params.deviceId,
      endpointId: params.endpointId,
      orgId: params.orgId,
      runtimeType: params.runtimeType,
      timestamp: params.timestamp,
      usb: {
        category: params.usbResult.category,
        confidence: params.usbResult.confidence,
        connectedDeviceCount: params.usbResult.connectedDeviceCount,
        detectionMethod: params.usbResult.detectionMethod,
        status: params.usbResult.status
      },
      web: canonicalWeb
    };

    const jsonStr = JSON.stringify(canonicalData);
    const hash = crypto.createHash('sha256').update(jsonStr, 'utf8').digest('hex');
    return `SHA256: ${hash}`;
  }

  /**
   * Run full endpoint compliance assessment with strict tenant & device isolation
   */
  public async runAssessment(params: {
    orgId: string;
    userId: string;
    deviceId: string;
  }): Promise<EndpointAssessment> {
    const { orgId, userId, deviceId } = params;

    if (!orgId || typeof orgId !== 'string') {
      throw new Error('Invalid organization ID: orgId is required');
    }
    if (!userId || typeof userId !== 'string') {
      throw new Error('Invalid user ID: userId is required');
    }
    if (!deviceId || typeof deviceId !== 'string') {
      throw new Error('DEVICE_IDENTITY_UNAVAILABLE: Trusted device identity is required');
    }

    // 1. Verify device belongs to authenticated tenant
    const devRow = this.db.prepare('SELECT device_id, org_id, revoked FROM devices WHERE device_id = ? AND org_id = ?').get(deviceId, orgId) as { device_id: string; org_id: string; revoked: number } | undefined;

    if (!devRow) {
      throw new Error(`DEVICE_IDENTITY_UNAVAILABLE: Device '${deviceId}' is not registered under organization '${orgId}'`);
    }

    if (devRow.revoked === 1) {
      throw new Error(`DEVICE_REVOKED: Device '${deviceId}' registration has been revoked`);
    }

    // 2. Initialize Provenance & Endpoint Identity
    const startedAt = new Date().toISOString();
    const platform = this.usbDetector.getPlatform();
    const hostname = os.hostname() || 'UNKNOWN';
    const architecture = os.arch();
    const osVersion = `${os.type()} ${os.release()}`;
    const machineUuid = getMachineUuid();

    const endpointMeta = this.getOrCreateEndpoint(orgId, deviceId, {
      hostname,
      platform,
      architecture,
      machineUuid
    });

    const endpointId = endpointMeta.endpointId;
    const deviceType: DeviceType = endpointMeta.deviceType;
    const runtimeType: RuntimeType = endpointMeta.runtimeType;
    const detectionSource: DetectionSource = 'LOCAL_MACHINE';
    const assessmentId = generateAssessmentId(new Date());

    // 3. Execute Detection Modules (USB + Web Access Probes)
    const [usbResult, webResults] = await Promise.all([
      this.usbDetector.detect(),
      this.webDetector.detectAll()
    ]);

    const completedAt = new Date().toISOString();

    // 4. Build Complete Provenance Object
    const provenance: AssessmentProvenance = {
      endpointId,
      assessmentId,
      deviceType,
      hostname,
      platform,
      architecture,
      runtimeType,
      detectionSource,
      machineUuid,
      agentVersion: AGENT_VERSION,
      applicationVersion: APPLICATION_VERSION,
      startedAt,
      completedAt,
      osVersion,
      runtimeVersion: process.version,
      scannerVersion: APPLICATION_VERSION
    };

    // Inject provenance into results
    usbResult.endpointId = endpointId;
    usbResult.assessmentId = assessmentId;
    usbResult.detectionSource = detectionSource;
    usbResult.runtimeType = runtimeType;
    usbResult.provenance = provenance;

    for (const webRes of webResults) {
      webRes.endpointId = endpointId;
      webRes.assessmentId = assessmentId;
      webRes.detectionSource = detectionSource;
      webRes.runtimeType = runtimeType;
      webRes.provenance = provenance;
    }

    // 5. Compute Category Summaries
    const categorySummaries: Record<DetectionCategory, CategorySummary> = {
      USB_STORAGE: {
        total: 1,
        accessible: usbResult.status === 'ENABLED' ? 1 : 0,
        blocked: usbResult.status === 'DISABLED' ? 1 : 0,
        indeterminate: ['UNKNOWN', 'REQUIRES_ELEVATION', 'UNSUPPORTED_PLATFORM'].includes(usbResult.status) ? 1 : 0,
        enabled: usbResult.status === 'ENABLED'
      },
      SOCIAL_MEDIA: this.summarizeWebCategory('SOCIAL_MEDIA', webResults),
      PERSONAL_EMAIL: this.summarizeWebCategory('PERSONAL_EMAIL', webResults),
      MESSAGING: this.summarizeWebCategory('MESSAGING', webResults),
      CLOUD_STORAGE: this.summarizeWebCategory('CLOUD_STORAGE', webResults)
    };

    // 6. Compute Overall Compliance Status
    const overallStatus = this.calculateOverallStatus(platform, usbResult, categorySummaries);

    // 7. Compute Deterministic Evidence Hash
    const evidenceHash = this.calculateEvidenceHash({
      assessmentId,
      endpointId,
      orgId,
      deviceId,
      timestamp: startedAt,
      detectionSource,
      runtimeType,
      usbResult,
      webResults
    });

    // 8. Generate Deterministic Evidence Text with Provenance
    const evidenceText = EndpointEvidenceGenerator.generateEvidenceText({
      id: assessmentId,
      endpoint_id: endpointId,
      org_id: orgId,
      device_id: deviceId,
      timestamp: startedAt,
      started_at: startedAt,
      completed_at: completedAt,
      platform,
      device_type: deviceType,
      runtime_type: runtimeType,
      detection_source: detectionSource,
      hostname,
      machine_uuid: machineUuid,
      application_version: APPLICATION_VERSION,
      agent_version: AGENT_VERSION,
      evidence_hash: evidenceHash,
      provenance,
      usb_result: usbResult,
      web_results: webResults,
      category_summaries: categorySummaries
    });

    const assessment: EndpointAssessment = {
      id: assessmentId,
      assessment_id: assessmentId,
      endpoint_id: endpointId,
      org_id: orgId,
      device_id: deviceId,
      user_id: userId,
      timestamp: startedAt,
      started_at: startedAt,
      completed_at: completedAt,
      platform,
      device_type: deviceType,
      runtime_type: runtimeType,
      detection_source: detectionSource,
      hostname,
      machine_uuid: machineUuid,
      application_version: APPLICATION_VERSION,
      agent_version: AGENT_VERSION,
      overall_status: overallStatus,
      evidence_hash: evidenceHash,
      provenance,
      usb_result: usbResult,
      web_results: webResults,
      category_summaries: categorySummaries,
      evidence_text: evidenceText,
      created_at: completedAt
    };

    // 9. Persist Assessment & Individual Detection Results to SQLite
    this.persistAssessment(assessment);

    return assessment;
  }

  /**
   * Helper to summarize web category probe statuses
   */
  private summarizeWebCategory(category: DetectionCategory, results: WebTargetResult[]): CategorySummary {
    const catResults = results.filter(r => r.category === category);
    const accessible = catResults.filter(r => r.status === 'ACCESSIBLE').length;
    const blocked = catResults.filter(r => r.status === 'BLOCKED').length;
    const indeterminate = catResults.filter(r => ['INDETERMINATE', 'UNREACHABLE', 'UNSUPPORTED'].includes(r.status)).length;

    return {
      total: catResults.length,
      accessible,
      blocked,
      indeterminate
    };
  }

  /**
   * Calculate overall compliance status from detection outcomes
   */
  private calculateOverallStatus(
    platform: string,
    usbResult: USBDetectionResult,
    summaries: Record<DetectionCategory, CategorySummary>
  ): AssessmentOverallStatus {
    if (platform !== 'windows') {
      return 'INDETERMINATE';
    }

    const anyAccessible =
      summaries.SOCIAL_MEDIA.accessible > 0 ||
      summaries.PERSONAL_EMAIL.accessible > 0 ||
      summaries.MESSAGING.accessible > 0 ||
      summaries.CLOUD_STORAGE.accessible > 0;

    const usbEnabled = usbResult.status === 'ENABLED';

    if (usbEnabled || anyAccessible) {
      return 'NON_COMPLIANT';
    }

    if (
      usbResult.status === 'DISABLED' &&
      summaries.SOCIAL_MEDIA.accessible === 0 &&
      summaries.PERSONAL_EMAIL.accessible === 0 &&
      summaries.MESSAGING.accessible === 0 &&
      summaries.CLOUD_STORAGE.accessible === 0
    ) {
      return 'COMPLIANT';
    }

    return 'ATTENTION_REQUIRED';
  }

  /**
   * Persist assessment and detection results with strict organization isolation
   */
  private persistAssessment(assessment: EndpointAssessment): void {
    const summaryJson = JSON.stringify({
      usb_result: assessment.usb_result,
      category_summaries: assessment.category_summaries,
      evidence_text: assessment.evidence_text
    });
    const provenanceJson = JSON.stringify(assessment.provenance);

    const insertAssessment = this.db.prepare(`
      INSERT INTO endpoint_assessments (
        id, endpoint_id, org_id, device_id, user_id, timestamp, started_at, completed_at,
        platform, device_type, runtime_type, detection_source, hostname, machine_uuid,
        application_version, agent_version, overall_status, evidence_hash, provenance_json, summary_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertAssessment.run(
      assessment.id,
      assessment.endpoint_id,
      assessment.org_id,
      assessment.device_id,
      assessment.user_id,
      assessment.timestamp,
      assessment.started_at,
      assessment.completed_at,
      assessment.platform,
      assessment.device_type,
      assessment.runtime_type,
      assessment.detection_source,
      assessment.hostname,
      assessment.machine_uuid,
      assessment.application_version,
      assessment.agent_version,
      assessment.overall_status,
      assessment.evidence_hash,
      provenanceJson,
      summaryJson,
      assessment.created_at
    );

    // Persist USB Detection Result
    const insertResult = this.db.prepare(`
      INSERT INTO endpoint_detection_results (
        id, assessment_id, category, target, status, confidence, detection_method, metadata_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertResult.run(
      `res-${crypto.randomUUID()}`,
      assessment.id,
      'USB_STORAGE',
      'USB_MASS_STORAGE',
      assessment.usb_result.status,
      assessment.usb_result.confidence,
      assessment.usb_result.detectionMethod,
      JSON.stringify({
        connectedDevices: assessment.usb_result.connectedStorageDevices,
        connectedCount: assessment.usb_result.connectedDeviceCount,
        policyDetails: assessment.usb_result.policyDetails,
        errorMessage: assessment.usb_result.errorMessage,
        endpointId: assessment.endpoint_id,
        detectionSource: assessment.detection_source,
        runtimeType: assessment.runtime_type
      }),
      assessment.created_at
    );

    // Persist Web Detection Results
    for (const webRes of assessment.web_results) {
      insertResult.run(
        `res-${crypto.randomUUID()}`,
        assessment.id,
        webRes.category,
        webRes.service,
        webRes.status,
        webRes.confidence,
        webRes.detectionMethod,
        JSON.stringify({
          target_domain: webRes.target_domain,
          httpStatusCode: webRes.httpStatusCode,
          reason: webRes.reason,
          responseTimeMs: webRes.responseTimeMs,
          endpointId: assessment.endpoint_id,
          detectionSource: assessment.detection_source,
          runtimeType: assessment.runtime_type
        }),
        assessment.created_at
      );
    }
  }

  /**
   * Retrieve an assessment by ID with strict tenant isolation
   */
  public getAssessmentById(assessmentId: string, orgId: string): EndpointAssessment | null {
    const row = this.db.prepare(`
      SELECT * FROM endpoint_assessments WHERE id = ? AND org_id = ?
    `).get(assessmentId, orgId) as any;

    if (!row) return null;

    return this.hydrateAssessment(row);
  }

  /**
   * List assessments for an organization
   */
  public listAssessments(orgId: string, limit: number = 20): EndpointAssessment[] {
    const rows = this.db.prepare(`
      SELECT * FROM endpoint_assessments WHERE org_id = ? ORDER BY timestamp DESC LIMIT ?
    `).all(orgId, limit) as any[];

    return rows.map(r => this.hydrateAssessment(r));
  }

  /**
   * Get latest assessment for an organization
   */
  public getLatestAssessment(orgId: string, deviceId?: string): EndpointAssessment | null {
    let row: any;
    if (deviceId) {
      row = this.db.prepare(`
        SELECT * FROM endpoint_assessments WHERE org_id = ? AND device_id = ? ORDER BY timestamp DESC LIMIT 1
      `).get(orgId, deviceId);
    } else {
      row = this.db.prepare(`
        SELECT * FROM endpoint_assessments WHERE org_id = ? ORDER BY timestamp DESC LIMIT 1
      `).get(orgId);
    }

    if (!row) return null;
    return this.hydrateAssessment(row);
  }

  /**
   * Hydrate assessment row and load all its detection results
   */
  private hydrateAssessment(row: any): EndpointAssessment {
    const results = this.db.prepare(`
      SELECT * FROM endpoint_detection_results WHERE assessment_id = ?
    `).all(row.id) as any[];

    let parsedSummary: any = {};
    try {
      parsedSummary = JSON.parse(row.summary_json || '{}');
    } catch {}

    let parsedProvenance: AssessmentProvenance | undefined;
    try {
      if (row.provenance_json) {
        parsedProvenance = JSON.parse(row.provenance_json);
      }
    } catch {}

    const endpointId = row.endpoint_id || parsedProvenance?.endpointId || generateEndpointId(`${row.org_id}:${row.device_id}`);
    const deviceType: DeviceType = row.device_type || parsedProvenance?.deviceType || (row.platform === 'windows' ? 'WINDOWS_ENDPOINT' : row.platform === 'linux' ? 'LINUX_ENDPOINT' : row.platform === 'darwin' ? 'MACOS_ENDPOINT' : 'UNKNOWN');
    const runtimeType: RuntimeType = row.runtime_type || parsedProvenance?.runtimeType || (row.platform === 'windows' ? 'LOCAL_WINDOWS_AGENT' : row.platform === 'linux' ? 'LOCAL_LINUX_AGENT' : row.platform === 'darwin' ? 'LOCAL_MACOS_AGENT' : 'UNKNOWN');
    const detectionSource: DetectionSource = row.detection_source || parsedProvenance?.detectionSource || 'LOCAL_MACHINE';
    const hostname = row.hostname || parsedProvenance?.hostname || 'UNKNOWN';
    const machineUuid = row.machine_uuid || parsedProvenance?.machineUuid || 'UNKNOWN';
    const startedAt = row.started_at || row.timestamp;
    const completedAt = row.completed_at || row.created_at || row.timestamp;
    const agentVersion = row.agent_version || parsedProvenance?.agentVersion || AGENT_VERSION;
    const applicationVersion = row.application_version || APPLICATION_VERSION;
    const evidenceHash = row.evidence_hash || 'SHA256: 0000000000000000000000000000000000000000000000000000000000000000';

    const provenance: AssessmentProvenance = parsedProvenance || {
      endpointId,
      assessmentId: row.id,
      deviceType,
      hostname,
      platform: row.platform,
      architecture: 'x64',
      runtimeType,
      detectionSource,
      machineUuid,
      agentVersion,
      applicationVersion,
      startedAt,
      completedAt
    };

    const usbRow = results.find(r => r.category === 'USB_STORAGE');
    let usbMeta: any = {};
    try {
      usbMeta = JSON.parse(usbRow?.metadata_json || '{}');
    } catch {}

    const usb_result: USBDetectionResult = parsedSummary.usb_result || {
      category: 'USB_STORAGE',
      status: usbRow?.status || 'UNKNOWN',
      connectedStorageDevices: usbMeta.connectedDevices || [],
      connectedDeviceCount: usbMeta.connectedCount || 0,
      detectionMethod: usbRow?.detection_method || 'WINDOWS_REGISTRY_QUERY',
      confidence: usbRow?.confidence || 'HIGH',
      timestamp: row.timestamp,
      platform: row.platform,
      endpointId,
      assessmentId: row.id,
      detectionSource,
      runtimeType,
      provenance,
      policyDetails: usbMeta.policyDetails,
      errorMessage: usbMeta.errorMessage
    };

    const web_results: WebTargetResult[] = results
      .filter(r => r.category !== 'USB_STORAGE')
      .map(r => {
        let meta: any = {};
        try {
          meta = JSON.parse(r.metadata_json || '{}');
        } catch {}
        return {
          category: r.category,
          service: r.target,
          target_domain: meta.target_domain || '',
          status: r.status,
          confidence: r.confidence,
          detectionMethod: r.detection_method,
          httpStatusCode: meta.httpStatusCode,
          reason: meta.reason,
          responseTimeMs: meta.responseTimeMs,
          timestamp: r.created_at,
          endpointId,
          assessmentId: row.id,
          detectionSource,
          runtimeType,
          provenance
        };
      });

    return {
      id: row.id,
      assessment_id: row.id,
      endpoint_id: endpointId,
      org_id: row.org_id,
      device_id: row.device_id,
      user_id: row.user_id,
      timestamp: row.timestamp,
      started_at: startedAt,
      completed_at: completedAt,
      platform: row.platform,
      device_type: deviceType,
      runtime_type: runtimeType,
      detection_source: detectionSource,
      hostname,
      machine_uuid: machineUuid,
      application_version: applicationVersion,
      agent_version: agentVersion,
      overall_status: row.overall_status,
      evidence_hash: evidenceHash,
      provenance,
      usb_result,
      web_results,
      category_summaries: parsedSummary.category_summaries || {
        USB_STORAGE: { total: 1, accessible: 0, blocked: 0, indeterminate: 0 },
        SOCIAL_MEDIA: { total: 0, accessible: 0, blocked: 0, indeterminate: 0 },
        PERSONAL_EMAIL: { total: 0, accessible: 0, blocked: 0, indeterminate: 0 },
        MESSAGING: { total: 0, accessible: 0, blocked: 0, indeterminate: 0 },
        CLOUD_STORAGE: { total: 0, accessible: 0, blocked: 0, indeterminate: 0 }
      },
      evidence_text: parsedSummary.evidence_text || '',
      created_at: row.created_at
    };
  }
}
