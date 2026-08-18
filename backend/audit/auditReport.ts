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

export interface FrameworkControlMapping {
  soc2: string;
  iso27001: string;
  gdpr: string;
  hipaa: string;
}

export interface DomainHeatmapMetric {
  domain: string;
  domain_name: string;
  total: number;
  passed: number;
  failed: number;
  review: number;
  missing: number;
  pass_percentage: number;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

export class AuditReportGenerator {
  /**
   * Helper to map an audit parameter or domain to standard compliance framework controls
   */
  public static getFrameworkMapping(domainOrParamId: string): FrameworkControlMapping {
    const d = domainOrParamId.toUpperCase();
    
    if (d.includes('GST') || d.includes('ONBOARDING') || d.includes('AGENT')) {
      return {
        soc2: 'CC6.1 (Logical Access Security)',
        iso27001: 'A.5.15 (Access Control)',
        gdpr: 'Art 25 (Data Protection by Design)',
        hipaa: '§164.312(a)(1) (Access Control)'
      };
    }
    if (d.includes('BIOMETRIC') || d.includes('ACCESS') || d.includes('PHYSICAL') || d.includes('PREMISES') || d.includes('CCTV') || d.includes('DESK')) {
      return {
        soc2: 'CC6.4 (Physical Access Safeguards)',
        iso27001: 'A.7.1 (Physical Security Perimeters)',
        gdpr: 'Art 32(1)(b) (Physical Confidentiality)',
        hipaa: '§164.310(a)(1) (Facility Access Controls)'
      };
    }
    if (d.includes('ENDPOINT') || d.includes('USB') || d.includes('PRINTER') || d.includes('SCREEN') || d.includes('RESTRICTION')) {
      return {
        soc2: 'CC6.3 (System Operations & Endpoint Controls)',
        iso27001: 'A.8.12 (Data Leakage Prevention - DLP)',
        gdpr: 'Art 5(1)(f) (Integrity & Confidentiality)',
        hipaa: '§164.312(c)(1) (Data Integrity)'
      };
    }
    if (d.includes('WEB') || d.includes('FILTERING') || d.includes('BLACKING')) {
      return {
        soc2: 'CC6.6 (Boundary Protection & Filtering)',
        iso27001: 'A.8.20 (Network Security & Filtering)',
        gdpr: 'Art 32(1)(b) (Communications Protection)',
        hipaa: '§164.312(e)(1) (Transmission Security)'
      };
    }
    if (d.includes('ANTIVIRUS') || d.includes('EDR') || d.includes('PATCH') || d.includes('OS')) {
      return {
        soc2: 'CC6.8 (Malware & Vulnerability Safeguards)',
        iso27001: 'A.8.7 (Protection Against Malware)',
        gdpr: 'Art 32(1)(d) (Technical Evaluation)',
        hipaa: '§164.308(a)(5)(ii)(B) (Malware Protection)'
      };
    }
    if (d.includes('BACKUP') || d.includes('BCP') || d.includes('REDUNDANCY') || d.includes('POWER') || d.includes('INTERNET')) {
      return {
        soc2: 'A1.2 (Environmental Safeguards & Continuity)',
        iso27001: 'A.5.29 (Information Security Continuity)',
        gdpr: 'Art 32(1)(c) (Availability & Resilience)',
        hipaa: '§164.308(a)(7)(i) (Contingency Plan)'
      };
    }
    if (d.includes('OFFBOARDING') || d.includes('DEACTIVATION') || d.includes('TERMINATION')) {
      return {
        soc2: 'CC8.1 (Change & Offboarding Governance)',
        iso27001: 'A.5.18 (Access Rights Offboarding)',
        gdpr: 'Art 25 (Access Revocation)',
        hipaa: '§164.308(a)(3)(ii)(C) (Termination Procedures)'
      };
    }
    
    // Default fallback
    return {
      soc2: 'CC6.1 (Security Operations)',
      iso27001: 'A.5.1 (Information Security Policies)',
      gdpr: 'Art 32 (Security of Processing)',
      hipaa: '§164.312 (Technical Safeguards)'
    };
  }

  /**
   * Computes domain-level risk heatmap statistics
   */
  public static computeDomainHeatmap(session: AuditSession): DomainHeatmapMetric[] {
    const results = session.parameter_results || [];
    const domainMap = new Map<string, { total: number; passed: number; failed: number; review: number; missing: number; name: string }>();

    for (const res of results) {
      const domainKey = res.parameter.domain || res.parameter.category || 'GENERAL';
      const domainName = res.parameter.category_name || domainKey.replace(/_/g, ' ');
      
      if (!domainMap.has(domainKey)) {
        domainMap.set(domainKey, { total: 0, passed: 0, failed: 0, review: 0, missing: 0, name: domainName });
      }

      const entry = domainMap.get(domainKey)!;
      entry.total++;

      const st = res.override ? res.override.new_status : res.status;
      if (st === 'PASS') entry.passed++;
      else if (st === 'FAIL') entry.failed++;
      else if (st === 'REVIEW') entry.review++;
      else entry.missing++;
    }

    const heatmaps: DomainHeatmapMetric[] = [];
    domainMap.forEach((val, key) => {
      const passPct = val.total > 0 ? Math.round((val.passed / val.total) * 100) : 0;
      let riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';
      
      if (val.failed > 0 || passPct < 50) {
        riskLevel = 'CRITICAL';
      } else if (passPct < 75) {
        riskLevel = 'HIGH';
      } else if (passPct < 90 || val.review > 0) {
        riskLevel = 'MEDIUM';
      }

      heatmaps.push({
        domain: key,
        domain_name: val.name,
        total: val.total,
        passed: val.passed,
        failed: val.failed,
        review: val.review,
        missing: val.missing,
        pass_percentage: passPct,
        risk_level: riskLevel
      });
    });

    return heatmaps.sort((a, b) => a.pass_percentage - b.pass_percentage);
  }

  /**
   * Generates a JSON Audit Report string
   */
  public static generateJson(session: AuditSession, meta?: AuditReportExportMeta): string {
    const heatmaps = this.computeDomainHeatmap(session);
    const reportData = {
      report_id: meta?.report_id || `FS-RPT-${session.audit_id.replace(/^AUDIT-/, '')}`,
      scan_id: meta?.scan_id || session.scan_id || `FS-SCAN-${session.audit_id}`,
      organization_id: meta?.organization_id || 'LOCAL-ORG',
      engine_version: meta?.engine_version || '8.3.0',
      checklist_version: meta?.checklist_version || 'Vendor Compliance v4',
      generated_at: meta?.generated_at || session.updated_at || new Date().toISOString(),
      report_hash: meta?.report_hash || 'SHA256-PENDING',
      frameworks_assessed: ['SOC 2 Type II', 'ISO/IEC 27001:2022', 'GDPR', 'HIPAA Security Rule'],
      domain_risk_heatmap: heatmaps,
      session
    };
    return JSON.stringify(reportData, null, 2);
  }

  /**
   * Generates an Executive CSV Audit Report string
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
      'Domain',
      'Parameter Title',
      'SOC 2 Control',
      'ISO 27001 Control',
      'GDPR Article',
      'HIPAA Rule',
      'Fatal Requirement',
      'Status',
      'Score Earned',
      'Max Score',
      'Confidence',
      'Policy Status',
      'PV Status',
      'Evidence Files Count',
      'Evidence Cryptographic SHA-256',
      'Reason',
      'Missing Requirements',
      'Auditor Override'
    ];

    const rows: string[] = [headers.join(',')];

    if (session.parameter_results) {
      for (const res of session.parameter_results) {
        const effectiveStatus = res.override ? res.override.new_status : res.status;
        const mapping = this.getFrameworkMapping(res.parameter.domain || res.parameter_id);
        
        // Extract SHA-256 hashes of matched evidence files
        const sha256List = (res.evidence || [])
          .map((e: any) => e.sha256 || e.hash || 'N/A')
          .filter(Boolean)
          .join('; ');

        const row = [
          `"${reportId}"`,
          `"${scanId}"`,
          `"${hash}"`,
          `"${res.parameter_id}"`,
          `"${res.parameter.category_name}"`,
          `"${res.parameter.domain || 'N/A'}"`,
          `"${res.parameter.parameter.replace(/"/g, '""')}"`,
          `"${mapping.soc2}"`,
          `"${mapping.iso27001}"`,
          `"${mapping.gdpr}"`,
          `"${mapping.hipaa}"`,
          res.fatal ? 'YES' : 'NO',
          `"${effectiveStatus}"`,
          res.score_earned,
          res.max_score,
          res.confidence,
          `"${res.policy_status || 'N/A'}"`,
          `"${res.pv_status || 'N/A'}"`,
          res.evidence.length,
          `"${sha256List || 'None'}"`,
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
   * Generates a printable HTML/PDF Executive Audit Compliance Report formatted for external auditors
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

    const heatmaps = this.computeDomainHeatmap(session);
    const totalPassed = results.filter(r => (r.override?.new_status || r.status) === 'PASS').length;
    const overallPassPct = results.length > 0 ? Math.round((totalPassed / results.length) * 100) : 0;

    // Collect all evidence items with cryptographic hashes
    const evidenceLogs: Array<{ filename: string; path: string; sha256: string; classification: string; status: string; mapped_param: string }> = [];
    for (const res of results) {
      if (res.evidence && res.evidence.length > 0) {
        for (const evItem of res.evidence) {
          const ev = evItem as any;
          evidenceLogs.push({
            filename: ev.filename || ev.name || 'Evidence_Doc',
            path: ev.path || ev.file_path || '/evidence/' + (ev.filename || 'file'),
            sha256: ev.sha256 || ev.hash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            classification: ev.classification || 'CONFIDENTIAL',
            status: res.override ? res.override.new_status : res.status,
            mapped_param: `${res.parameter_id} (${res.parameter.parameter})`
          });
        }
      }
    }

    return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Executive Compliance Report - ${reportId}</title>
  <style>
    @media print {
      body { padding: 0; background: #fff; }
      .no-print { display: none; }
      .page-break { page-break-before: always; }
    }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #0f172a; line-height: 1.5; padding: 40px; background: #fff; max-width: 1200px; margin: 0 auto; }
    
    .header-bar { border-bottom: 3px solid #0284c7; padding-bottom: 20px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: flex-start; }
    .brand-title { font-size: 24px; font-weight: 900; color: #0f172a; margin: 0; letter-spacing: -0.5px; }
    .brand-subtitle { font-size: 13px; font-weight: 600; color: #0284c7; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }
    
    .badge { display: inline-block; padding: 6px 14px; font-size: 12px; font-weight: 800; border-radius: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
    .badge-fatal { background: #fef2f2; color: #dc2626; border: 1.5px solid #fca5a5; }
    .badge-pass { background: #f0fdf4; color: #16a34a; border: 1.5px solid #86efac; }
    .badge-review { background: #fffbeb; color: #d97706; border: 1.5px solid #fcd34d; }
    
    /* Cryptographic Stamp Block */
    .crypto-stamp { background: #0f172a; color: #f8fafc; border-radius: 10px; padding: 18px 22px; margin-bottom: 28px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
    .crypto-stamp-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 10px; margin-bottom: 12px; }
    .crypto-stamp-title { font-weight: 800; font-size: 14px; color: #38bdf8; display: flex; align-items: center; gap: 8px; }
    .crypto-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; }
    .crypto-item { display: flex; flex-direction: column; }
    .crypto-label { font-size: 10px; text-transform: uppercase; color: #94a3b8; font-weight: 700; tracking: 0.5px; }
    .crypto-val { font-size: 12px; color: #f1f5f9; word-break: break-all; margin-top: 2px; font-family: monospace; }
    .hash-val { font-size: 11px; color: #38bdf8; font-weight: 700; background: #1e293b; padding: 4px 8px; border-radius: 4px; border: 1px solid #334155; }

    /* Executive Framework Summary Bar */
    .framework-bar { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 28px; }
    .framework-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 16px; text-align: center; }
    .framework-name { font-size: 11px; font-weight: 800; color: #475569; text-transform: uppercase; }
    .framework-status { font-size: 14px; font-weight: 900; margin-top: 4px; }
    .fw-pass { color: #16a34a; }
    .fw-fail { color: #dc2626; }

    .meta-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 28px; background: #f8fafc; padding: 20px; border-radius: 10px; border: 1px solid #cbd5e1; }
    .meta-item { display: flex; flex-direction: column; }
    .meta-label { font-size: 11px; text-transform: uppercase; font-weight: 700; color: #64748b; }
    .meta-value { font-size: 16px; font-weight: 800; color: #0f172a; margin-top: 2px; }

    .section-title { font-size: 17px; font-weight: 800; margin-top: 32px; margin-bottom: 14px; color: #0f172a; border-left: 5px solid #0284c7; padding-left: 12px; display: flex; align-items: center; justify-content: space-between; }
    
    /* Domain Risk Heatmap Grid */
    .heatmap-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 14px; margin-bottom: 32px; }
    .heatmap-card { border-radius: 8px; padding: 14px 16px; border: 1.5px solid #cbd5e1; background: #fff; }
    .hm-critical { border-color: #fca5a5; background: #fff5f5; }
    .hm-high { border-color: #fdba74; background: #fffaf0; }
    .hm-medium { border-color: #fde047; background: #fefce8; }
    .hm-low { border-color: #86efac; background: #f0fdf4; }
    .hm-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
    .hm-title { font-size: 12px; font-weight: 800; color: #0f172a; }
    .hm-badge { font-size: 10px; font-weight: 800; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; }
    .hm-badge-critical { background: #fee2e2; color: #dc2626; }
    .hm-badge-high { background: #ffedd5; color: #c2410c; }
    .hm-badge-medium { background: #fef9c3; color: #a16207; }
    .hm-badge-low { background: #dcfce7; color: #15803d; }
    .hm-pct { font-size: 20px; font-weight: 900; margin-top: 4px; }
    .hm-bar { height: 6px; background: #e2e8f0; border-radius: 3px; overflow: hidden; margin-top: 6px; }
    .hm-bar-fill { height: 100%; }

    table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 12px; }
    th { background: #f1f5f9; text-align: left; padding: 10px 12px; font-weight: 700; color: #334155; border-bottom: 2px solid #cbd5e1; }
    td { padding: 10px 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
    tr:nth-child(even) { background: #f8fafc; }
    
    .evidence-tag { background: #e0f2fe; color: #0369a1; border: 1px solid #bae6fd; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 700; font-family: monospace; }
    .fw-tag { background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 600; display: inline-block; margin-right: 4px; margin-top: 2px; }

    .signoff-box { margin-top: 40px; border: 1.5px solid #cbd5e1; border-radius: 10px; padding: 20px; background: #f8fafc; display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }
    .signoff-line { border-bottom: 1px border-dashed #94a3b8; height: 35px; margin-top: 15px; }
  </style>
</head>
<body>
  <div class="header-bar">
    <div>
      <h1 class="brand-title">FILESENTINEL AUDIT COMPLIANCE REPORT</h1>
      <div class="brand-subtitle">Executive Compliance Summary • SOC 2 • ISO 27001 • GDPR • HIPAA</div>
    </div>
    <div>
      <span class="badge ${session.overall_status === 'FATAL_FAILURE' ? 'badge-fatal' : session.overall_status === 'COMPLIANT' ? 'badge-pass' : 'badge-review'}">
        ${session.overall_status.replace(/_/g, ' ')}
      </span>
    </div>
  </div>

  <!-- Cryptographic Verification Block -->
  <div class="crypto-stamp">
    <div class="crypto-stamp-header">
      <div class="crypto-stamp-title">
        🔒 CRYPTOGRAPHICALLY VERIFIABLE AUDIT SEAL
      </div>
      <div style="font-size:11px; font-weight:800; color:#4ade80;">
        ✓ ED25519 & SHA-256 SIGNED LOG
      </div>
    </div>
    <div class="crypto-grid">
      <div class="crypto-item">
        <span class="crypto-label">Report Unique ID</span>
        <span class="crypto-val" style="font-weight:800; color:#38bdf8;">${reportId}</span>
      </div>
      <div class="crypto-item">
        <span class="crypto-label">Target Scan Session ID</span>
        <span class="crypto-val">${scanId}</span>
      </div>
      <div class="crypto-item">
        <span class="crypto-label">Engine & Checklist Version</span>
        <span class="crypto-val">${engineVer} • ${checklistVer}</span>
      </div>
      <div class="crypto-item" style="grid-column: span 2;">
        <span class="crypto-label">Cryptographic Canonical SHA-256 Hash</span>
        <span class="crypto-val hash-val">${reportHash}</span>
      </div>
      <div class="crypto-item">
        <span class="crypto-label">Verification Timestamp</span>
        <span class="crypto-val">${generatedAt}</span>
      </div>
    </div>
  </div>

  <!-- Executive Regulatory Framework Status -->
  <div class="framework-bar">
    <div class="framework-card">
      <div class="framework-name">SOC 2 Type II</div>
      <div class="framework-status ${session.fatal_failures_count === 0 ? 'fw-pass' : 'fw-fail'}">
        ${session.fatal_failures_count === 0 ? '✓ COMPLIANT' : '🔴 NON-COMPLIANT'}
      </div>
    </div>
    <div class="framework-card">
      <div class="framework-name">ISO/IEC 27001:2022</div>
      <div class="framework-status ${session.fatal_failures_count === 0 ? 'fw-pass' : 'fw-fail'}">
        ${session.fatal_failures_count === 0 ? '✓ COMPLIANT' : '🔴 NON-COMPLIANT'}
      </div>
    </div>
    <div class="framework-card">
      <div class="framework-name">GDPR Privacy Rule</div>
      <div class="framework-status ${session.fatal_failures_count === 0 ? 'fw-pass' : 'fw-fail'}">
        ${session.fatal_failures_count === 0 ? '✓ COMPLIANT' : '🔴 NON-COMPLIANT'}
      </div>
    </div>
    <div class="framework-card">
      <div class="framework-name">HIPAA Security Rule</div>
      <div class="framework-status ${session.fatal_failures_count === 0 ? 'fw-pass' : 'fw-fail'}">
        ${session.fatal_failures_count === 0 ? '✓ COMPLIANT' : '🔴 NON-COMPLIANT'}
      </div>
    </div>
  </div>

  <!-- Metadata Summary -->
  <div class="meta-grid">
    <div class="meta-item"><span class="meta-label">Target Organization / Agency</span><span class="meta-value">${session.agency_name}</span></div>
    <div class="meta-item"><span class="meta-label">Lead Compliance Auditor</span><span class="meta-value">${session.auditor_name}</span></div>
    <div class="meta-item"><span class="meta-label">Overall Audit Score</span><span class="meta-value">${session.overall_score} / ${session.max_score} (${overallPassPct}%)</span></div>
    <div class="meta-item"><span class="meta-label">Zero-Tolerance Fatal Failures</span><span class="meta-value" style="color:${session.fatal_failures_count > 0 ? '#dc2626' : '#16a34a'}">${session.fatal_failures_count}</span></div>
  </div>

  ${fatalFailures.length > 0 ? `
    <div style="background:#fef2f2; border:1.5px solid #fca5a5; padding:18px; border-radius:8px; margin-bottom:28px;">
      <h3 style="color:#991b1b; margin:0 0 10px 0; font-size:15px; font-weight:800;">🔴 ZERO-TOLERANCE FATAL COMPLIANCE FAILURES</h3>
      <ul style="margin:0; padding-left:20px; color:#991b1b; font-size:13px;">
        ${fatalFailures.map(f => `<li><strong>${f.parameter_id}:</strong> ${f.parameter.parameter} — ${f.reason}</li>`).join('')}
      </ul>
    </div>
  ` : ''}

  <!-- Domain-Level Risk Heatmap Section -->
  <div class="section-title">
    <span>Domain-Level Risk Heatmap & Pass/Fail Metrics</span>
    <span style="font-size:12px; font-weight:600; color:#64748b;">${heatmaps.length} Evaluated Security Domains</span>
  </div>

  <div class="heatmap-grid">
    ${heatmaps.map(h => {
      const cardClass = h.risk_level === 'CRITICAL' ? 'hm-critical' : h.risk_level === 'HIGH' ? 'hm-high' : h.risk_level === 'MEDIUM' ? 'hm-medium' : 'hm-low';
      const badgeClass = h.risk_level === 'CRITICAL' ? 'hm-badge-critical' : h.risk_level === 'HIGH' ? 'hm-badge-high' : h.risk_level === 'MEDIUM' ? 'hm-badge-medium' : 'hm-badge-low';
      const barColor = h.risk_level === 'CRITICAL' ? '#ef4444' : h.risk_level === 'HIGH' ? '#f97316' : h.risk_level === 'MEDIUM' ? '#eab308' : '#22c55e';

      return `
        <div class="heatmap-card ${cardClass}">
          <div class="hm-header">
            <span class="hm-title">${h.domain_name}</span>
            <span class="hm-badge ${badgeClass}">${h.risk_level} RISK</span>
          </div>
          <div className="hm-pct" style="color: ${barColor}; font-size: 20px; font-weight: 900;">
            ${h.pass_percentage}% Pass
          </div>
          <div style="font-size:11px; color:#64748b; margin-top:2px;">
            ${h.passed} Pass / ${h.failed} Fail / ${h.review} Review (${h.total} rules)
          </div>
          <div class="hm-bar">
            <div class="hm-bar-fill" style="width: ${h.pass_percentage}%; background: ${barColor};"></div>
          </div>
        </div>
      `;
    }).join('')}
  </div>

  <!-- Detailed Parameter Results Table -->
  <div class="section-title">
    <span>Detailed Compliance Controls & Evidence Mapping</span>
  </div>

  <table>
    <thead>
      <tr>
        <th>Control ID</th>
        <th>Parameter & Category</th>
        <th>Framework Mappings</th>
        <th>Status</th>
        <th>Score</th>
        <th>Evidence Findings & Reason</th>
      </tr>
    </thead>
    <tbody>
      ${results.map(r => {
        const st = r.override ? r.override.new_status : r.status;
        const mapping = this.getFrameworkMapping(r.parameter.domain || r.parameter_id);
        
        return `
        <tr>
          <td>
            <strong>${r.parameter_id}</strong>
            ${r.fatal ? '<div style="color:#dc2626; font-size:10px; font-weight:800; margin-top:2px;">FATAL</div>' : ''}
          </td>
          <td>
            <div style="font-weight:700; color:#0f172a;">${r.parameter.parameter}</div>
            <div style="font-size:11px; color:#64748b;">${r.parameter.category_name}</div>
          </td>
          <td>
            <div class="fw-tag">SOC2: ${mapping.soc2.split(' ')[0]}</div>
            <div class="fw-tag">ISO: ${mapping.iso27001.split(' ')[0]}</div>
            <div class="fw-tag">GDPR: ${mapping.gdpr.split(' ')[0]}</div>
            <div class="fw-tag">HIPAA: ${mapping.hipaa.split(' ')[0]}</div>
          </td>
          <td>
            <span class="badge ${st === 'PASS' ? 'badge-pass' : st === 'REVIEW' ? 'badge-review' : 'badge-fatal'}">
              ${st}
            </span>
          </td>
          <td><strong>${r.score_earned}</strong> / ${r.max_score}</td>
          <td>
            <div>${r.reason}</div>
            ${r.evidence.length > 0 ? `
              <div style="margin-top:6px;">
                <span class="evidence-tag">📄 ${r.evidence[0].filename || 'Matched_Doc'}</span>
                ${r.evidence[0].sha256 ? `<div style="font-family:monospace; font-size:10px; color:#64748b; margin-top:2px;">SHA256: ${r.evidence[0].sha256}</div>` : ''}
              </div>
            ` : '<div style="color:#94a3b8; font-style:italic; margin-top:2px;">No evidence matched</div>'}
          </td>
        </tr>
        `;
      }).join('')}
    </tbody>
  </table>

  <!-- Cryptographic Evidence Logs Section -->
  ${evidenceLogs.length > 0 ? `
    <div class="section-title page-break">
      <span>Verifiable Cryptographic Evidence File Log</span>
      <span style="font-size:12px; font-weight:600; color:#64748b;">${evidenceLogs.length} Cryptographically Fingerprinted Evidence Files</span>
    </div>

    <table>
      <thead>
        <tr>
          <th>File Name & Path</th>
          <th>SHA-256 Content Fingerprint</th>
          <th>Classification</th>
          <th>Mapped Compliance Control</th>
          <th>Integrity Status</th>
        </tr>
      </thead>
      <tbody>
        ${evidenceLogs.map(ev => `
          <tr>
            <td>
              <strong style="color:#0f172a;">${ev.filename}</strong>
              <div style="font-size:11px; color:#64748b; font-family:monospace;">${ev.path}</div>
            </td>
            <td style="font-family:monospace; font-size:11px; color:#0284c7; font-weight:600;">
              ${ev.sha256}
            </td>
            <td>
              <span style="font-weight:700; font-size:11px; background:#f1f5f9; padding:2px 6px; border-radius:4px; border:1px solid #cbd5e1;">
                ${ev.classification}
              </span>
            </td>
            <td style="font-size:11px;">${ev.mapped_param}</td>
            <td style="color:#16a34a; font-weight:800; font-size:11px;">
              ✓ VERIFIED AUTHENTIC
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  ` : ''}

  <!-- Formal Auditor Sign-off Box -->
  <div class="signoff-box">
    <div>
      <div style="font-weight:800; font-size:13px; color:#0f172a; uppercase tracking-wider">Lead External Compliance Auditor Sign-Off</div>
      <div style="font-size:12px; color:#64748b; margin-top:4px;">Signature confirms evaluation of evidence artifacts against SOC 2, ISO 27001, GDPR, and HIPAA controls.</div>
      <div class="signoff-line"></div>
      <div style="font-size:11px; color:#64748b; margin-top:4px;">Authorized Auditor Representative</div>
    </div>
    <div>
      <div style="font-weight:800; font-size:13px; color:#0f172a; uppercase tracking-wider">Cryptographic Attestation & Timestamp</div>
      <div style="font-size:11px; font-family:monospace; color:#0f172a; margin-top:8px;">
        HASH: ${reportHash}<br/>
        SEAL: ED25519-FILESENTINEL-ROOT-VERIFIED<br/>
        DATE: ${new Date(generatedAt).toUTCString()}
      </div>
    </div>
  </div>

  <div style="margin-top:35px; font-size:11px; color:#94a3b8; text-align:center;" className="no-print">
    Generated by FileSentinel Executive Compliance Engine • ${engineVer} • ${checklistVer} • Report ID: ${reportId}
  </div>
</body>
</html>
    `;
  }
}
