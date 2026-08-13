import { AuditSession } from './models.js';

export class AuditReportGenerator {
  /**
   * Generates a JSON Audit Report string
   */
  public static generateJson(session: AuditSession): string {
    return JSON.stringify(session, null, 2);
  }

  /**
   * Generates a CSV Audit Report string
   */
  public static generateCsv(session: AuditSession): string {
    const headers = [
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
  public static generateHtml(session: AuditSession): string {
    const results = session.parameter_results || [];
    const fatalFailures = results.filter(r => (r.override?.new_status || r.status) === 'FAIL' && r.fatal);

    return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>FileSentinel Audit Compliance Report - ${session.audit_id}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1e293b; line-height: 1.5; padding: 40px; background: #fff; }
    .header { border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: flex-start; }
    .title { font-size: 24px; font-weight: 700; color: #0f172a; margin: 0; }
    .subtitle { font-size: 14px; color: #64748b; margin-top: 4px; }
    .badge { display: inline-block; padding: 6px 12px; font-size: 13px; font-weight: 700; border-radius: 6px; text-transform: uppercase; }
    .badge-fatal { background: #fef2f2; color: #dc2626; border: 1px solid #fca5a5; }
    .badge-pass { background: #f0fdf4; color: #16a34a; border: 1px solid #86efac; }
    .badge-review { background: #fffbeeb; color: #d97706; border: 1px solid #fcd34d; }
    .badge-fail { background: #fef2f2; color: #dc2626; border: 1px solid #fca5a5; }
    .meta-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; background: #f8fafc; padding: 20px; border-radius: 8px; border: 1px solid #e2e8f0; }
    .meta-item { display: flex; flex-direction: column; }
    .meta-label { font-size: 11px; text-transform: uppercase; font-weight: 600; color: #64748b; }
    .meta-value { font-size: 16px; font-weight: 700; color: #0f172a; margin-top: 2px; }
    .section-title { font-size: 18px; font-weight: 700; margin-top: 30px; margin-bottom: 15px; color: #0f172a; border-left: 4px solid #2563eb; padding-left: 10px; }
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
      <div class="subtitle">AI-Assisted Evidence Verification & Regulatory Assessment</div>
    </div>
    <div>
      <span class="badge ${session.overall_status === 'FATAL_FAILURE' ? 'badge-fatal' : session.overall_status === 'COMPLIANT' ? 'badge-pass' : 'badge-review'}">
        ${session.overall_status.replace(/_/g, ' ')}
      </span>
    </div>
  </div>

  <div class="meta-grid">
    <div class="meta-item"><span class="meta-label">Audit ID</span><span class="meta-value">${session.audit_id}</span></div>
    <div class="meta-item"><span class="meta-label">Audit Date</span><span class="meta-value">${session.audit_date}</span></div>
    <div class="meta-item"><span class="meta-label">Agency Name</span><span class="meta-value">${session.agency_name}</span></div>
    <div class="meta-item"><span class="meta-label">Auditor</span><span class="meta-value">${session.auditor_name}</span></div>
    <div class="meta-item"><span class="meta-label">Compliance Score</span><span class="meta-value">${session.overall_score} / ${session.max_score}</span></div>
    <div class="meta-item"><span class="meta-label">Total Parameters</span><span class="meta-value">${session.total_parameters}</span></div>
    <div class="meta-item"><span class="meta-label">PASS / FAIL / REVIEW</span><span class="meta-value">${session.pass_count} / ${session.fail_count} / ${session.review_count}</span></div>
    <div class="meta-item"><span class="meta-label">Fatal Failures</span><span class="meta-value" style="color:${session.fatal_failures_count > 0 ? '#dc2626' : '#16a34a'}">${session.fatal_failures_count}</span></div>
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
    Generated by FileSentinel AI-Assisted Audit Engine • ${new Date().toISOString()}
  </div>
</body>
</html>
    `;
  }
}
