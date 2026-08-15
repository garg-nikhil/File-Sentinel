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

  async getDashboardStats(): Promise<DashboardStats> {
    const res = await fetch('/api/dashboard/stats');
    return res.json();
  },

  async startScan(rootPath: string): Promise<ScanSession> {
    const res = await fetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ root_path: rootPath })
    });
    return res.json();
  },

  async getScanProgress(scanId: string): Promise<ScanSession> {
    const res = await fetch(`/api/scans/${scanId}/progress`);
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
  }
};
