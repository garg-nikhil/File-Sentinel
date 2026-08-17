/**
 * FILE-SENTINEL — Phase A: Endpoint Compliance Detection Engine
 * Central Coordinator & Tenant-Scoped Compliance Engine
 *
 * STRICTLY DETECTION ONLY:
 * - NO remediation or system state modification
 * - Pure discovery, classification, reporting, and evidence generation
 */

import os from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
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
  EndpointPlatform
} from './endpointTypes.js';
import { USBDetector, USBDetectorConfig } from './usbDetector.js';
import { WebAccessDetector, WebAccessDetectorOptions } from './webAccessDetector.js';
import { EndpointEvidenceGenerator } from './endpointEvidence.js';

export const APPLICATION_VERSION = '8.2.0-PhaseA';

function detectHostPlatform(): EndpointPlatform {
  const current = os.platform();
  if (current === 'win32') return 'windows';
  if (current === 'linux') return 'linux';
  if (current === 'darwin') return 'darwin';
  return 'unsupported';
}

const currentHostPlatform = detectHostPlatform();

/**
 * Local Endpoint Agent Runtime Abstraction.
 * In Phase A, detection probes execute locally on the host machine where the application
 * or local agent daemon is running. Cloud-hosted instances cannot directly inspect client
 * physical hardware without an installed local agent provider.
 */
export const LOCAL_WINDOWS_AGENT_RUNTIME: EndpointRuntimeProvider = {
  type: 'LOCAL_WINDOWS_AGENT',
  platform: currentHostPlatform,
  isLocalExecution: true,
  runtimeDescription: `Local FileSentinel agent runtime running directly on the monitored ${currentHostPlatform} endpoint machine.`
};

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
      type: 'LOCAL_WINDOWS_AGENT',
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

    // 2. Execute Detection Modules (USB + Web Access Probes)
    const timestamp = new Date().toISOString();
    const assessmentId = `EP-ASM-${crypto.randomUUID()}`;
    const platform = this.usbDetector.getPlatform();

    const [usbResult, webResults] = await Promise.all([
      this.usbDetector.detect(),
      this.webDetector.detectAll()
    ]);

    // 3. Compute Category Summaries
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

    // 4. Compute Overall Compliance Status
    const overallStatus = this.calculateOverallStatus(platform, usbResult, categorySummaries);

    // 5. Generate Deterministic Evidence Text
    const evidenceText = EndpointEvidenceGenerator.generateEvidenceText({
      id: assessmentId,
      org_id: orgId,
      device_id: deviceId,
      timestamp,
      platform,
      application_version: APPLICATION_VERSION,
      usb_result: usbResult,
      web_results: webResults,
      category_summaries: categorySummaries
    });

    const assessment: EndpointAssessment = {
      id: assessmentId,
      org_id: orgId,
      device_id: deviceId,
      user_id: userId,
      timestamp,
      platform,
      application_version: APPLICATION_VERSION,
      overall_status: overallStatus,
      usb_result: usbResult,
      web_results: webResults,
      category_summaries: categorySummaries,
      evidence_text: evidenceText,
      created_at: timestamp
    };

    // 6. Persist Assessment & Individual Detection Results to SQLite
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

    const insertAssessment = this.db.prepare(`
      INSERT INTO endpoint_assessments (
        id, org_id, device_id, user_id, timestamp, platform, application_version, overall_status, summary_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertAssessment.run(
      assessment.id,
      assessment.org_id,
      assessment.device_id,
      assessment.user_id,
      assessment.timestamp,
      assessment.platform,
      assessment.application_version,
      assessment.overall_status,
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
        errorMessage: assessment.usb_result.errorMessage
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
          responseTimeMs: webRes.responseTimeMs
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
          timestamp: r.created_at
        };
      });

    return {
      id: row.id,
      org_id: row.org_id,
      device_id: row.device_id,
      user_id: row.user_id,
      timestamp: row.timestamp,
      platform: row.platform,
      application_version: row.application_version,
      overall_status: row.overall_status,
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
