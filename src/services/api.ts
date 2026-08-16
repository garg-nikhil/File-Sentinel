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
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to start scan');
    }
    return res.json();
  },

  async uploadDirectory(files: File[], onProgress?: (pct: number) => void): Promise<string> {
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
          resolve(res.root_path);
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
  }
};
