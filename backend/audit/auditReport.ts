import { AuditSession } from './models.js';

export interface AuditReportExportMeta {
  report_id?: string;
  scan_id?: string;
  organization_id?: string;
  engine_version?: string;
  checklist_version?: string;
  generated_at?: string;
  report_hash?: string;
}

export class AuditReportGenerator {
  /**
   * Generates a JSON Audit Report string
   */
  public static generateJson(session: AuditSession, meta?: AuditReportExportMeta): string {
    const reportData = {
      report_id: meta?.report_id || `FS-RPT-${session.audit_id.replace(/^AUDIT-/, '')}`,
      scan_id: meta?.scan_id || session.scan_id || `FS-SCAN-${session.audit_id}`,
      organization_id: meta?.organization_id || 'LOCAL-ORG',
      engine_version: meta?.engine_version || '8.3.0',
      checklist_version: meta?.checklist_version || 'Vendor Compliance v4',
      generated_at: meta?.generated_at || session.updated_at || new Date().toISOString(),
      report_hash: meta?.report_hash || 'SHA256-PENDING',
      session
    };
    return JSON.stringify(reportData, null, 2);
  }

  /**
   * Generates a CSV Audit Report string
   */
  public static generateCsv(session: AuditSession, meta?: AuditReportExportMeta): string {
    const reportId = meta?.report_id || `FS-RPT-${session.audit_id.replace(/^AUDIT-/, '')}`;
    const scanId = meta?.scan_id || session.scan_id || `FS-SCAN-${session.audit_id}`;
    const hash = meta?.report_hash || 'N/A';

    const headers = [
      'Report ID',
      'Scan ID',
      'Report Hash',
      'Parameter ID',
      'Category',
      'Parameter Title',
      'Fatal Requirement',
      'Status',
      'Score Earned',
      'Max Score',
      'Confidence',
      'Policy Status',
      'Police Verification Status',
      'Evidence Files Count',
      'Reason',
      'Missing Requirements',
      'Auditor Override'
    ];

    const rows: string[] = [headers.join(',')];

    if (session.parameter_results) {
      for (const res of session.parameter_results) {
        const effectiveStatus = res.override ? res.override.new_status : res.status;
        const row = [
          `"${reportId}"`,
          `"${scanId}"`,
          `"${hash}"`,
          `"${res.parameter_id}"`,
          `"${res.parameter.category_name}"`,
          `"${res.parameter.parameter.replace(/"/g, '""')}"`,
          res.fatal ? 'YES' : 'NO',
          `"${effectiveStatus}"`,
          res.score_earned,
          res.max_score,
          res.confidence,
          `"${res.policy_status || 'N/A'}"`,
          `"${res.pv_status || 'N/A'}"`,
          res.evidence.length,
          `"${res.reason.replace(/"/g, '""')}"`,
          `"${res.missing_requirements.join('; ').replace(/"/g, '""')}"`,
          res.override ? `"${res.override.auditor_name}: ${res.override.comment}"` : '"None"'
        ];
        rows.push(row.join(','));
      }
    }

    return rows.join('\n');
  }

  /**
   * Generates a printable HTML Audit Report (used directly in browser print or converted to PDF)
   */
  public static generateHtml(session: AuditSession, meta?: AuditReportExportMeta): string {
    const results = session.parameter_results || [];
    const fatalFailures = results.filter(r => (r.override?.new_status || r.status) === 'FAIL' && r.fatal);
    const reportId = meta?.report_id || `FS-RPT-${session.audit_id.replace(/^AUDIT-/, '')}`;
    const scanId = meta?.scan_id || session.scan_id || `FS-SCAN-${session.audit_id}`;
    const engineVer = meta?.engine_version || '8.3.0';
    const checklistVer = meta?.checklist_version || 'Vendor Compliance v4';
    const generatedAt = meta?.generated_at || session.updated_at || new Date().toISOString();
    const reportHash = meta?.report_hash || 'SHA256-PENDING';

    return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>FileSentinel Audit Compliance Report - ${reportId}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1e293b; line-height: 1.5; padding: 40px; background: #fff; }
    .header { border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: flex-start; }
    .title { font-size: 22px; font-weight: 800; color: #0f172a; margin: 0; letter-spacing: -0.5px; }
    .subtitle { font-size: 13px; color: #64748b; margin-top: 4px; }
    .badge { display: inline-block; padding: 6px 12px; font-size: 12px; font-weight: 800; border-radius: 6px; text-transform: uppercase; }
    .badge-fatal { background: #fef2f2; color: #dc2626; border: 1px solid #fca5a5; }
    .badge-pass { background: #f0fdf4; color: #16a34a; border: 1px solid #86efac; }
    .badge-review { background: #fffbeb; color: #d97706; border: 1px solid #fcd34d; }
    .badge-fail { background: #fef2f2; color: #dc2626; border: 1px solid #fca5a5; }
    
    .crypto-stamp { background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; padding: 14px 18px; margin-bottom: 24px; font-family: monospace; font-size: 12px; }
    .crypto-stamp-title { font-weight: 700; color: #0f172a; margin-bottom: 8px; display: flex; align-items: center; justify-content: space-between; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .crypto-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
    .crypto-item { display: flex; flex-direction: column; }
    .crypto-label { font-size: 10px; text-transform: uppercase; color: #64748b; font-weight: 600; }
    .crypto-val { font-size: 12px; color: #0f172a; word-break: break-all; margin-top: 2px; }
    .hash-val { font-family: monospace; font-size: 11px; color: #2563eb; font-weight: 600; }

    .meta-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 25px; background: #f8fafc; padding: 18px; border-radius: 8px; border: 1px solid #e2e8f0; }
    .meta-item { display: flex; flex-direction: column; }
    .meta-label { font-size: 11px; text-transform: uppercase; font-weight: 600; color: #64748b; }
    .meta-value { font-size: 15px; font-weight: 700; color: #0f172a; margin-top: 2px; }
    .section-title { font-size: 16px; font-weight: 700; margin-top: 28px; margin-bottom: 12px; color: #0f172a; border-left: 4px solid #2563eb; padding-left: 10px; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
    th { background: #f1f5f9; text-align: left; padding: 10px 12px; font-weight: 600; color: #475569; border-bottom: 1px solid #cbd5e1; }
    td { padding: 10px 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
    tr:nth-child(even) { background: #f8fafc; }
    .evidence-tag { background: #e2e8f0; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; color: #334155; }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1 class="title">FILESENTINEL AUDIT COMPLIANCE REPORT</h1>
      <div class="subtitle">Cryptographically Verifiable Audit & Regulatory Assessment</div>
    </div>
    <div>
      <span class="badge ${session.overall_status === 'FATAL_FAILURE' ? 'badge-fatal' : session.overall_status === 'COMPLIANT' ? 'badge-pass' : 'badge-review'}">
        ${session.overall_status.replace(/_/g, ' ')}
      </span>
    </div>
  </div>

  <!-- Cryptographic Verification Header -->
  <div class="crypto-stamp">
    <div class="crypto-stamp-title">
      <span>🔒 Cryptographic Audit Integrity Record</span>
      <span style="color:#16a34a; font-size:11px; font-weight:700;">✓ SERVER VERIFIABLE</span>
    </div>
    <div class="crypto-grid">
      <div class="crypto-item">
        <span class="crypto-label">Report ID</span>
        <span class="crypto-val" style="font-weight:700;">${reportId}</span>
      </div>
      <div class="crypto-item">
        <span class="crypto-label">Scan ID</span>
        <span class="crypto-val">${scanId}</span>
      </div>
      <div class="crypto-item">
        <span class="crypto-label">Engine / Checklist</span>
        <span class="crypto-val">${engineVer} • ${checklistVer}</span>
      </div>
      <div class="crypto-item" style="grid-column: span 2;">
        <span class="crypto-label">SHA-256 Report Hash</span>
        <span class="crypto-val hash-val">${reportHash}</span>
      </div>
      <div class="crypto-item">
        <span class="crypto-label">Generated At</span>
        <span class="crypto-val">${generatedAt}</span>
      </div>
    </div>
  </div>

  <div class="meta-grid">
    <div class="meta-item"><span class="meta-label">Agency Name</span><span class="meta-value">${session.agency_name}</span></div>
    <div class="meta-item"><span class="meta-label">Auditor</span><span class="meta-value">${session.auditor_name}</span></div>
    <div class="meta-item"><span class="meta-label">Compliance Score</span><span class="meta-value">${session.overall_score} / ${session.max_score}</span></div>
    <div class="meta-item"><span class="meta-label">Total Parameters</span><span class="meta-value">${session.total_parameters}</span></div>
    <div class="meta-item"><span class="meta-label">PASS / FAIL / REVIEW</span><span class="meta-value">${session.pass_count} / ${session.fail_count} / ${session.review_count}</span></div>
    <div class="meta-item"><span class="meta-label">Fatal Failures</span><span class="meta-value" style="color:${session.fatal_failures_count > 0 ? '#dc2626' : '#16a34a'}">${session.fatal_failures_count}</span></div>
    <div class="meta-item"><span class="meta-label">Audit Date</span><span class="meta-value">${session.audit_date}</span></div>
    <div class="meta-item"><span class="meta-label">Audit Session ID</span><span class="meta-value">${session.audit_id}</span></div>
  </div>

  ${fatalFailures.length > 0 ? `
    <div style="background:#fef2f2; border:1px solid #fca5a5; padding:15px; border-radius:8px; margin-bottom:20px;">
      <h3 style="color:#991b1b; margin:0 0 8px 0; font-size:15px;">🔴 CRITICAL FATAL FAILURES DETECTED</h3>
      <ul style="margin:0; padding-left:20px; color:#991b1b; font-size:13px;">
        ${fatalFailures.map(f => `<li><strong>${f.parameter_id}:</strong> ${f.parameter.parameter} — ${f.reason}</li>`).join('')}
      </ul>
    </div>
  ` : ''}

  <div class="section-title">Audit Checklist Parameters Breakdown</div>
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Category</th>
        <th>Parameter</th>
        <th>Fatal</th>
        <th>Status</th>
        <th>Score</th>
        <th>Evidence & Reason</th>
      </tr>
    </thead>
    <tbody>
      ${results.map(r => {
        const st = r.override ? r.override.new_status : r.status;
        return `
        <tr>
          <td><strong>${r.parameter_id}</strong></td>
          <td>${r.parameter.category_name}</td>
          <td>${r.parameter.parameter}</td>
          <td>${r.fatal ? '<strong style="color:#dc2626">YES</strong>' : 'NO'}</td>
          <td>
            <span class="badge ${st === 'PASS' ? 'badge-pass' : st === 'REVIEW' ? 'badge-review' : 'badge-fail'}">
              ${st}
            </span>
          </td>
          <td>${r.score_earned}/${r.max_score}</td>
          <td>
            <div>${r.reason}</div>
            ${r.evidence.length > 0 ? `<div style="margin-top:4px;"><span class="evidence-tag">📄 ${r.evidence[0].filename}</span></div>` : '<div style="color:#94a3b8; font-style:italic;">No file matched</div>'}
            ${r.override ? `<div style="font-size:11px; color:#0284c7; margin-top:4px;">✏️ Overridden by ${r.override.auditor_name}: ${r.override.comment}</div>` : ''}
          </td>
        </tr>
        `;
      }).join('')}
    </tbody>
  </table>

  <div style="margin-top:40px; font-size:11px; color:#94a3b8; text-align:center;">
    Generated by FileSentinel Verifiable Audit Engine • ${engineVer} • ${checklistVer} • Report ID: ${reportId}
  </div>
</body>
</html>
    `;
  }
}
