import {
  AppSettings,
  DashboardStats,
  FileItem,
  Finding,
  QuarantineItem,
  Rule,
  ScanSession
} from '../types.js';

export const api = {
  async getHealth() {
    const res = await fetch('/api/health');
    return res.json();
  },

  async getSettings(): Promise<AppSettings> {
    const res = await fetch('/api/settings');
    return res.json();
  },

  async updateSettings(settings: Partial<AppSettings>): Promise<AppSettings> {
    const res = await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    return res.json();
  },

  async triggerScheduledScanNow(): Promise<{ success: boolean; result: any }> {
    const res = await fetch('/api/settings/scheduler/trigger-now', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to trigger scheduled scan');
    }
    return res.json();
  },

  async getScheduledScanHistory(): Promise<any[]> {
    const res = await fetch('/api/settings/scheduler/history');
    if (!res.ok) return [];
    const data = await res.json();
    return data.history || [];
  },

  async getDashboardStats(): Promise<DashboardStats> {
    const res = await fetch('/api/dashboard/stats');
    return res.json();
  },

  async startScan(rootPaths: string | string[]): Promise<ScanSession> {
    const res = await fetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ root_paths: Array.isArray(rootPaths) ? rootPaths : [rootPaths] })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to start scan');
    }
    return res.json();
  },

  async uploadDirectory(files: File[], onProgress?: (pct: number) => void): Promise<{ rootPath: string; fileCount: number; folderName: string }> {
    const formData = new FormData();
    const uploadId = 'scan_' + Math.random().toString(36).substring(2, 10);
    formData.append('uploadId', uploadId);
    
    for (const file of files) {
      // Use webkitRelativePath if available, fallback to file.name
      const relativePath = (file as any).webkitRelativePath || file.name;
      formData.append('files', file, relativePath);
    }

    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/scans/upload-target');
      
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable && onProgress) {
          onProgress(Math.round((e.loaded / e.total) * 100));
        }
      };

      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          const res = JSON.parse(xhr.responseText);
          const firstPath = files[0] && (files[0] as any).webkitRelativePath ? (files[0] as any).webkitRelativePath : files[0]?.name || 'Uploaded Folder';
          const topFolder = firstPath.split('/')[0] || 'Uploaded Folder';
          resolve({
            rootPath: res.root_path,
            fileCount: res.file_count || files.length,
            folderName: topFolder
          });
        } else {
          try {
            const err = JSON.parse(xhr.responseText);
            reject(new Error(err.error || 'Upload failed'));
          } catch {
            reject(new Error('Upload failed'));
          }
        }
      };
      
      xhr.onerror = () => reject(new Error('Network error during upload'));
      xhr.send(formData);
    });
  },

  async getScanProgress(scanId: string): Promise<ScanSession> {
    const res = await fetch(`/api/scans/${scanId}/progress`);
    return res.json();
  },

  async pauseScan(scanId: string): Promise<{ success: boolean; scan: ScanSession }> {
    const res = await fetch(`/api/scans/${scanId}/pause`, {
      method: 'POST'
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to pause scan');
    }
    return res.json();
  },

  async resumeScan(scanId: string): Promise<ScanSession> {
    const res = await fetch(`/api/scans/${scanId}/resume`, {
      method: 'POST'
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to resume scan');
    }
    return res.json();
  },

  async getScanFiles(scanId: string): Promise<FileItem[]> {
    const res = await fetch(`/api/scans/${scanId}/files`);
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to fetch scan files');
    }
    return res.json();
  },

  async getScanHistory(): Promise<ScanSession[]> {
    const res = await fetch('/api/scans');
    return res.json();
  },

  async getFiles(params?: { scan_id?: string; classification?: string }): Promise<FileItem[]> {
    const query = new URLSearchParams(params as any).toString();
    const res = await fetch(`/api/files${query ? `?${query}` : ''}`);
    return res.json();
  },

  async getFileDetail(fileId: string): Promise<FileItem> {
    const res = await fetch(`/api/files/${fileId}`);
    return res.json();
  },

  async analyzeFileWithAI(fileId: string) {
    const res = await fetch(`/api/files/${fileId}/analyze-ai`, {
      method: 'POST'
    });
    return res.json();
  },

  async getFindings(): Promise<Finding[]> {
    const res = await fetch('/api/findings');
    return res.json();
  },

  async getRules(): Promise<Rule[]> {
    const res = await fetch('/api/rules');
    return res.json();
  },

  async toggleRule(id: string, enabled: boolean) {
    const res = await fetch(`/api/rules/${id}/toggle`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled })
    });
    return res.json();
  },

  async createRule(rule: Partial<Rule>) {
    const res = await fetch('/api/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rule)
    });
    return res.json();
  },

  async getQuarantineItems(): Promise<QuarantineItem[]> {
    const res = await fetch('/api/quarantine');
    return res.json();
  },

  async quarantineFile(fileId: string) {
    const res = await fetch(`/api/quarantine/${fileId}`, {
      method: 'POST'
    });
    return res.json();
  },



  async getAuditLogs() {
    const res = await fetch('/api/audit-logs');
    return res.json();
  },

  // --- AUDIT COMPLIANCE SERVICES ---
  async runAuditScan(params?: {
    target_dir?: string;
    scan_roots?: string[];
    scan_id?: string;
    audit_date?: string;
    agency_name?: string;
    auditor_name?: string;
  }) {
    const res = await fetch('/api/audit/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params || {})
    });
    return res.json();
  },

  async getAuditSessions() {
    const res = await fetch('/api/audit/sessions');
    return res.json();
  },

  async getAuditSessionDetail(auditId: string) {
    const res = await fetch(`/api/audit/session/${auditId}`);
    return res.json();
  },

  async submitAuditorOverride(params: {
    audit_id: string;
    parameter_id: string;
    new_status: string;
    auditor_name: string;
    comment?: string;
  }) {
    const res = await fetch('/api/audit/override', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params)
    });
    return res.json();
  },

  async getAuditChecklist() {
    const res = await fetch('/api/audit/checklist');
    return res.json();
  },

  async getEvidenceGaps(auditId: string) {
    const res = await fetch(`/api/audit/gaps/${auditId}`);
    return res.json();
  },

  async getCloudUploads() {
    const res = await fetch('/api/cloud-uploads');
    return res.json();
  },

  async uploadSelectedFiles(fileIds: string[]) {
    const res = await fetch('/api/cloud-uploads/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ file_ids: fileIds })
    });
    return res.json();
  },

  async uploadAllFiles(scanId?: string) {
    const res = await fetch('/api/cloud-uploads/upload-all', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_id: scanId })
    });
    return res.json();
  },

  async retryCloudUpload(fileId: string) {
    const res = await fetch(`/api/cloud-uploads/retry/${fileId}`, {
      method: 'POST'
    });
    return res.json();
  },

  async getLicense() {
    const res = await fetch('/api/license');
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to fetch license');
    }
    return res.json();
  },

  async getLicenseDevices() {
    const res = await fetch('/api/license/devices');
    return res.json();
  },

  async activateLicenseDevice(deviceId?: string) {
    const res = await fetch('/api/license/devices/activate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: deviceId })
    });
    return res.json();
  },

  async deactivateLicenseDevice(deviceId: string) {
    const res = await fetch('/api/license/devices/deactivate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: deviceId })
    });
    return res.json();
  },

  async getLicenseEvents() {
    const res = await fetch('/api/license/events');
    return res.json();
  },

  // --- PRIVACY-PRESERVING TELEMETRY SERVICES ---
  async getScanTelemetryHistory(limit: number = 50, offset: number = 0) {
    const res = await fetch(`/api/scans/history?limit=${limit}&offset=${offset}`);
    return res.json();
  },

  async getScanTelemetryDetail(scanId: string) {
    const res = await fetch(`/api/scans/${scanId}`);
    return res.json();
  },

  async postScanTelemetry(payload: any) {
    const res = await fetch('/api/telemetry/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  async getTelemetryQueueStatus() {
    const res = await fetch('/api/telemetry/queue/status');
    return res.json();
  },

  async flushTelemetryQueue() {
    const res = await fetch('/api/telemetry/queue/flush', {
      method: 'POST'
    });
    return res.json();
  },

  // --- VENDOR CLOUD DASHBOARD API ---
  async getCloudDashboardOverview() {
    const res = await fetch('/api/cloud-dashboard/overview');
    return res.json();
  },

  async getCloudComplianceTrend(limit: number = 30) {
    const res = await fetch(`/api/cloud-dashboard/trend?limit=${limit}`);
    return res.json();
  },

  async verifyCloudReport(queryId: string) {
    const res = await fetch('/api/cloud-dashboard/verify-report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query_id: queryId })
    });
    return res.json();
  },

  async getCloudOrganizationInfo() {
    const res = await fetch('/api/cloud-dashboard/organization');
    return res.json();
  },

  async getCloudSoftwareVersion() {
    const res = await fetch('/api/cloud-dashboard/software-version');
    return res.json();
  },

  async getCloudUsers() {
    const res = await fetch('/api/users');
    return res.json();
  },

  async createCloudUser(payload: { username: string; password: string; role: string }) {
    const res = await fetch('/api/users/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  async toggleCloudUserDisable(userId: string) {
    const res = await fetch(`/api/users/${userId}/toggle-disable`, {
      method: 'POST'
    });
    return res.json();
  },

  async updateCloudUserRole(userId: string, role: string) {
    const res = await fetch(`/api/users/${userId}/role`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role })
    });
    return res.json();
  },

  async removeCloudUser(userId: string) {
    const res = await fetch(`/api/users/${userId}`, {
      method: 'DELETE'
    });
    return res.json();
  },

  async getCloudDevices() {
    const res = await fetch('/api/devices');
    return res.json();
  },

  async revokeCloudDevice(deviceId: string) {
    const res = await fetch(`/api/devices/${deviceId}/revoke`, {
      method: 'POST'
    });
    return res.json();
  },

  // --- COMMERCIALIZATION PHASE 5: SUBSCRIPTION BILLING ---
  async getBillingState(): Promise<import('../types').OrganizationBillingState> {
    const res = await fetch('/api/billing/state');
    return res.json();
  },

  async getBillingPlans(): Promise<import('../types').BillingPlanInfo[]> {
    const res = await fetch('/api/billing/plans');
    return res.json();
  },

  async createSubscriptionCheckout(payload: { plan_key: string; interval: 'MONTHLY' | 'ANNUAL'; email?: string }) {
    const res = await fetch('/api/billing/checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  async changeSubscriptionPlan(payload: { new_plan_key: string; interval: 'MONTHLY' | 'ANNUAL' }) {
    const res = await fetch('/api/billing/change-plan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  async cancelSubscription() {
    const res = await fetch('/api/billing/cancel', {
      method: 'POST'
    });
    return res.json();
  },

  // --- COMMERCIALIZATION PHASE 8: PRIVACY-FIRST DATA GOVERNANCE ---
  async getPrivacyGovernance(): Promise<import('../types').GovernanceManifest> {
    const res = await fetch('/api/privacy/governance');
    return res.json();
  },

  async getTelemetryInspection(scanId: string): Promise<import('../types').TelemetryInspectionResult> {
    const res = await fetch(`/api/privacy/telemetry-preview/${scanId}`);
    return res.json();
  },

  async getRetentionPolicy(): Promise<import('../types').RetentionPolicy> {
    const res = await fetch('/api/privacy/retention-policy');
    return res.json();
  },

  async updateRetentionPolicy(payload: { cloud_metadata_retention_days: number; auto_purge_enabled?: boolean }) {
    const res = await fetch('/api/privacy/retention-policy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  async purgeExpiredCloudTelemetry() {
    const res = await fetch('/api/privacy/purge-cloud-telemetry', {
      method: 'POST'
    });
    return res.json();
  },

  // --- COMMERCIALIZATION PHASE 9: CRYPTOGRAPHICALLY VERIFIABLE AUDIT REPORTS ---
  async verifyReportPublic(reportId: string): Promise<import('../types').ReportVerificationResult> {
    const res = await fetch(`/api/reports/verify/${encodeURIComponent(reportId)}`);
    return res.json();
  },

  async registerAuditReport(payload: {
    scan_id?: string;
    audit_id?: string;
    engine_version?: string;
    checklist_version?: string;
  }) {
    const res = await fetch('/api/reports/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  async getAuditReportsList(): Promise<import('../types').StoredAuditReportItem[]> {
    const res = await fetch('/api/reports/list');
    return res.json();
  },

  async revokeAuditReport(reportId: string, reason: string) {
    const res = await fetch(`/api/reports/revoke/${encodeURIComponent(reportId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason })
    });
    return res.json();
  },

  // --- ENDPOINT COMPLIANCE DETECTION ENGINE (PHASE A & B) ---
  async runEndpointAssessment(payload?: {
    linkAuditSessionId?: string;
  }): Promise<import('../types').EndpointAssessment> {
    const res = await fetch('/api/endpoint/assess', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload || {})
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Assessment failed' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  },

  async getEndpointAssessments(limit: number = 20): Promise<import('../types').EndpointAssessment[]> {
    const res = await fetch(`/api/endpoint/assessments?limit=${limit}`);
    if (!res.ok) return [];
    return res.json();
  },

  async getEndpointAssessmentById(id: string): Promise<import('../types').EndpointAssessment> {
    const res = await fetch(`/api/endpoint/assessment/${encodeURIComponent(id)}`);
    if (!res.ok) {
      throw new Error(`Assessment ${id} not found`);
    }
    return res.json();
  },

  async getLatestEndpointAssessment(deviceId?: string): Promise<import('../types').EndpointAssessment | null> {
    const query = deviceId ? `?deviceId=${encodeURIComponent(deviceId)}` : '';
    const res = await fetch(`/api/endpoint/latest${query}`);
    if (!res.ok) return null;
    return res.json();
  },

  async getEndpoints(): Promise<import('../types').EndpointRecord[]> {
    const res = await fetch('/api/endpoint/endpoints');
    if (!res.ok) return [];
    return res.json();
  },

  async getEndpointById(id: string): Promise<import('../types').EndpointRecord> {
    const res = await fetch(`/api/endpoint/endpoints/${encodeURIComponent(id)}`);
    if (!res.ok) {
      throw new Error(`Endpoint ${id} not found`);
    }
    return res.json();
  },

  async getEndpointTargets(): Promise<import('../types').WebAccessTarget[]> {
    const res = await fetch('/api/endpoint/targets');
    if (!res.ok) return [];
    return res.json();
  },

  async getOfflineLicenseStatus() {
    const res = await fetch('/api/license/offline-status');
    if (!res.ok) {
      throw new Error('Failed to fetch offline license status');
    }
    return res.json();
  },

  async revalidateOfflineLicense() {
    const res = await fetch('/api/license/revalidate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || err.details || 'Failed to revalidate license clock');
    }
    return res.json();
  },

  async logClockMonitorHeartbeat(metrics: { deltaMs: number; elapsedPerformanceMs: number; elapsedDateMs: number; status: string }) {
    const res = await fetch('/api/license/clock-monitor/heartbeat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(metrics)
    });
    if (!res.ok) {
      throw new Error('Failed to log clock monitor heartbeat');
    }
    return res.json();
  },

  async getClockMonitorLogs(): Promise<Array<{ id: string; timestamp: string; delta_ms: number; elapsed_performance_ms: number; elapsed_date_ms: number; status: string }>> {
    const res = await fetch('/api/license/clock-monitor/logs');
    if (!res.ok) {
      throw new Error('Failed to fetch clock monitor forensic logs');
    }
    return res.json();
  }
};
