import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertOctagon,
  Search,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  FileText,
  Lock,
  ExternalLink,
  Copy,
  Check,
  RefreshCw,
  Clock,
  Fingerprint,
  Building2,
  Calendar,
  Sparkles,
  Ban
} from 'lucide-react';
import { api } from '../services/api';
import { ReportVerificationResult, StoredAuditReportItem } from '../types';

export const ReportVerificationView: React.FC = () => {
  const [reportIdInput, setReportIdInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ReportVerificationResult | null>(null);
  const [recentReports, setRecentReports] = useState<StoredAuditReportItem[]>([]);
  const [copiedHash, setCopiedHash] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [revocationReason, setRevocationReason] = useState('');
  const [revoking, setRevoking] = useState(false);

  useEffect(() => {
    loadRecentReports();
  }, []);

  const loadRecentReports = async () => {
    try {
      const list = await api.getAuditReportsList();
      if (Array.isArray(list)) {
        setRecentReports(list);
      }
    } catch (e) {
      console.error('Failed to load reports list:', e);
    }
  };

  const handleVerify = async (idToVerify?: string) => {
    const id = (idToVerify || reportIdInput).trim();
    if (!id) return;
    setLoading(true);
    try {
      const res = await api.verifyReportPublic(id);
      setResult(res);
      setReportIdInput(id);
    } catch (err: any) {
      setResult({
        status: 'INVALID',
        message: err.message || 'Network error during report verification'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleRevoke = async (reportId: string) => {
    if (!revocationReason.trim()) {
      alert('Please enter a reason for revocation.');
      return;
    }
    setRevoking(true);
    try {
      await api.revokeAuditReport(reportId, revocationReason.trim());
      setRevokingId(null);
      setRevocationReason('');
      await loadRecentReports();
      if (result && (result.report_id === reportId || result.scan_id === reportId)) {
        await handleVerify(reportId);
      }
    } catch (err: any) {
      alert(`Revocation failed: ${err.message}`);
    } finally {
      setRevoking(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto p-4 md:p-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-indigo-600/10 text-indigo-500 rounded-xl border border-indigo-500/20">
            <Fingerprint className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              FileSentinel Report Verification
              <span className="px-2 py-0.5 text-[10px] font-mono bg-indigo-500/10 text-indigo-400 rounded border border-indigo-500/20">
                PHASE 9
              </span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Zero-Knowledge Cryptographic Integrity Verification & Public Registry
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="px-3 py-1 bg-emerald-500/10 text-emerald-400 text-xs font-mono font-bold rounded-lg border border-emerald-500/20 flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5" /> Deterministic SHA-256
          </span>
        </div>
      </div>

      {/* Verification Search Bar */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="max-w-2xl mx-auto space-y-3">
          <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400">
            Enter Report ID or Verification Identifier
          </label>
          <div className="flex items-center gap-2">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                id="report-verify-input"
                type="text"
                value={reportIdInput}
                onChange={e => setReportIdInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleVerify()}
                placeholder="e.g. FS-RPT-8A91C2 or AUDIT-..."
                className="w-full bg-slate-950 border border-slate-800 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 rounded-lg pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 transition-all font-mono"
              />
            </div>
            <button
              id="verify-report-btn"
              onClick={() => handleVerify()}
              disabled={loading || !reportIdInput.trim()}
              className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-semibold rounded-lg transition-colors flex items-center gap-2 shadow"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
              Verify Report
            </button>
          </div>
          <p className="text-[11px] text-slate-500">
            Audit reports are verified against authoritative server SHA-256 cryptographic hashes without disclosing confidential document text or PII.
          </p>
        </div>
      </div>

      {/* Verification Result Display */}
      {result && (
        <div
          id="verification-result-card"
          className={`border rounded-xl p-6 space-y-6 transition-all ${
            result.status === 'VALID'
              ? 'bg-emerald-950/20 border-emerald-500/30'
              : result.status === 'REVOKED'
              ? 'bg-amber-950/20 border-amber-500/30'
              : 'bg-rose-950/20 border-rose-500/30'
          }`}
        >
          {/* Status Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div className="flex items-center gap-3">
              {result.status === 'VALID' && (
                <div className="p-3 bg-emerald-500/10 text-emerald-400 rounded-xl border border-emerald-500/30">
                  <CheckCircle2 className="w-7 h-7" />
                </div>
              )}
              {result.status === 'REVOKED' && (
                <div className="p-3 bg-amber-500/10 text-amber-400 rounded-xl border border-amber-500/30">
                  <AlertTriangle className="w-7 h-7" />
                </div>
              )}
              {result.status === 'INVALID' && (
                <div className="p-3 bg-rose-500/10 text-rose-400 rounded-xl border border-rose-500/30">
                  <XCircle className="w-7 h-7" />
                </div>
              )}

              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Status</span>
                  {result.status === 'VALID' && (
                    <span className="px-2.5 py-0.5 bg-emerald-500/20 text-emerald-300 font-extrabold text-xs rounded-full border border-emerald-500/30 flex items-center gap-1">
                      ✓ VERIFIED (VALID)
                    </span>
                  )}
                  {result.status === 'REVOKED' && (
                    <span className="px-2.5 py-0.5 bg-amber-500/20 text-amber-300 font-extrabold text-xs rounded-full border border-amber-500/30 flex items-center gap-1">
                      ⚠️ REVOKED
                    </span>
                  )}
                  {result.status === 'INVALID' && (
                    <span className="px-2.5 py-0.5 bg-rose-500/20 text-rose-300 font-extrabold text-xs rounded-full border border-rose-500/30 flex items-center gap-1">
                      ✕ INVALID
                    </span>
                  )}
                </div>
                <h2 className="text-lg font-bold text-slate-100 mt-0.5 font-mono">
                  Report: {result.report_id || reportIdInput}
                </h2>
              </div>
            </div>

            {result.status === 'VALID' && (
              <a
                href={`/api/audit/report/${result.report_id}/html`}
                target="_blank"
                rel="noreferrer"
                className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors flex items-center gap-1.5 self-start border border-slate-700"
              >
                <FileText className="w-3.5 h-3.5 text-indigo-400" /> View Printable Report
              </a>
            )}
          </div>

          {/* Invalid / Revoked Explanations */}
          {result.status === 'INVALID' && (
            <div className="p-4 bg-rose-900/30 border border-rose-500/30 rounded-lg text-rose-300 text-xs leading-relaxed">
              <p className="font-bold flex items-center gap-1.5">
                <AlertOctagon className="w-4 h-4" /> Integrity Verification Failed
              </p>
              <p className="mt-1">
                {result.message || 'The specified Report ID was not found or cryptographic hash comparison failed. If the report contents were modified, the hash changes and validation fails.'}
              </p>
            </div>
          )}

          {result.status === 'REVOKED' && (
            <div className="p-4 bg-amber-900/30 border border-amber-500/30 rounded-lg text-amber-300 text-xs leading-relaxed space-y-1">
              <p className="font-bold flex items-center gap-1.5">
                <Ban className="w-4 h-4" /> Report Has Been Revoked
              </p>
              <p>Reason: {result.revocation_reason || 'Administrative revocation'}</p>
              {result.revoked_at && <p className="text-[11px] opacity-80">Revoked on: {result.revoked_at}</p>}
            </div>
          )}

          {/* Report Metadata Grid */}
          {(result.status === 'VALID' || result.status === 'REVOKED') && (
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 bg-slate-950/60 p-4 rounded-xl border border-slate-800/80">
              <div>
                <span className="text-[10px] uppercase font-bold text-slate-500">Scan ID</span>
                <p className="text-xs font-mono font-semibold text-slate-200 mt-0.5 truncate">{result.scan_id || 'N/A'}</p>
              </div>
              <div>
                <span className="text-[10px] uppercase font-bold text-slate-500">Generated</span>
                <p className="text-xs font-semibold text-slate-200 mt-0.5">{result.generated_at || result.audit_date || 'N/A'}</p>
              </div>
              <div>
                <span className="text-[10px] uppercase font-bold text-slate-500">Engine Version</span>
                <p className="text-xs font-semibold text-slate-200 mt-0.5 font-mono">{result.engine_version || '8.3.0'}</p>
              </div>
              <div>
                <span className="text-[10px] uppercase font-bold text-slate-500">Checklist Version</span>
                <p className="text-xs font-semibold text-slate-200 mt-0.5 font-mono">{result.checklist_version || 'Vendor Compliance v4'}</p>
              </div>
            </div>
          )}

          {/* Cryptographic Hash Verification Card */}
          {result.report_hash && (
            <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <Fingerprint className="w-3.5 h-3.5 text-indigo-400" /> Canonical Report Hash (SHA-256)
                </span>
                <button
                  onClick={() => copyToClipboard(result.report_hash!)}
                  className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1 font-mono transition-colors"
                >
                  {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedHash ? 'Copied' : 'Copy Hash'}
                </button>
              </div>
              <div className="p-2.5 bg-slate-900 rounded font-mono text-xs text-indigo-300 break-all border border-slate-800">
                {result.report_hash}
              </div>
            </div>
          )}

          {/* Metrics Overview (Non-sensitive statistics only) */}
          {result.metrics && (
            <div className="space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                Verified Compliance Statistics (Non-Sensitive)
              </h3>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 bg-slate-950/50 rounded-lg border border-slate-800 text-center">
                  <span className="text-[10px] uppercase text-slate-500 font-bold">Overall Score</span>
                  <div className="text-lg font-bold text-emerald-400 font-mono mt-0.5">
                    {result.metrics.overall_score} / {result.metrics.max_score}
                  </div>
                </div>
                <div className="p-3 bg-slate-950/50 rounded-lg border border-slate-800 text-center">
                  <span className="text-[10px] uppercase text-slate-500 font-bold">Parameters</span>
                  <div className="text-lg font-bold text-slate-200 font-mono mt-0.5">
                    {result.metrics.total_parameters} Total
                  </div>
                </div>
                <div className="p-3 bg-slate-950/50 rounded-lg border border-slate-800 text-center">
                  <span className="text-[10px] uppercase text-slate-500 font-bold">Pass / Fail</span>
                  <div className="text-lg font-bold text-slate-200 font-mono mt-0.5">
                    {result.metrics.pass_count} / {result.metrics.fail_count}
                  </div>
                </div>
                <div className="p-3 bg-slate-950/50 rounded-lg border border-slate-800 text-center">
                  <span className="text-[10px] uppercase text-slate-500 font-bold">Fatal Failures</span>
                  <div className={`text-lg font-bold font-mono mt-0.5 ${result.metrics.fatal_failures_count > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                    {result.metrics.fatal_failures_count}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Privacy Notice Box */}
          <div className="p-3.5 bg-slate-950/60 border border-slate-800/80 rounded-lg flex items-start gap-2.5 text-slate-400 text-xs">
            <Lock className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <strong className="text-slate-300">Privacy & Confidentiality Guarantee:</strong> This verification response contains only zero-knowledge integrity hashes and aggregate scores. Document text, filenames, OCR contents, PII, and evidence snippets are strictly kept local on the scanning host.
            </div>
          </div>
        </div>
      )}

      {/* Registry of Reports */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <FileText className="w-4 h-4 text-indigo-400" /> Registered Verifiable Reports
            </h2>
            <p className="text-xs text-slate-500">
              Audit reports exported by your organization and registered for third-party verification
            </p>
          </div>
          <button
            onClick={loadRecentReports}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition-colors flex items-center gap-1 border border-slate-700"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Refresh List
          </button>
        </div>

        {recentReports.length === 0 ? (
          <div className="p-8 text-center bg-slate-950/40 rounded-xl border border-slate-800/80 text-slate-500 text-xs">
            No audit reports have been exported or registered yet. Export an audit report from the Audit Compliance engine to generate verifiable records.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase font-semibold">
                  <th className="py-2.5 px-3">Report ID</th>
                  <th className="py-2.5 px-3">Scan ID</th>
                  <th className="py-2.5 px-3">Engine / Checklist</th>
                  <th className="py-2.5 px-3">SHA-256 Hash</th>
                  <th className="py-2.5 px-3">Generated At</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {recentReports.map(rpt => (
                  <tr key={rpt.report_id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-3 font-mono font-bold text-indigo-300">
                      {rpt.report_id}
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-400">
                      {rpt.scan_id}
                    </td>
                    <td className="py-3 px-3 text-slate-300 font-mono text-[11px]">
                      {rpt.engine_version} • {rpt.checklist_version}
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-400 text-[11px]">
                      <span title={rpt.report_hash} className="bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                        {rpt.report_hash.substring(0, 10)}...{rpt.report_hash.substring(rpt.report_hash.length - 6)}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-400 whitespace-nowrap">
                      {rpt.generated_at.replace('T', ' ').substring(0, 16)}
                    </td>
                    <td className="py-3 px-3">
                      {rpt.status === 'VALID' ? (
                        <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-400 font-bold rounded text-[11px] border border-emerald-500/30">
                          VALID
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 bg-amber-500/20 text-amber-400 font-bold rounded text-[11px] border border-amber-500/30" title={rpt.revocation_reason || ''}>
                          REVOKED
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-right space-x-2 whitespace-nowrap">
                      <button
                        onClick={() => handleVerify(rpt.report_id)}
                        className="px-2.5 py-1 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 font-semibold rounded border border-indigo-500/30 transition-colors"
                      >
                        Verify
                      </button>
                      {rpt.status === 'VALID' && (
                        <button
                          onClick={() => setRevokingId(rpt.report_id)}
                          className="px-2.5 py-1 bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 font-semibold rounded border border-rose-500/30 transition-colors"
                        >
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Revocation Modal */}
      {revokingId && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-md w-full space-y-4 shadow-xl">
            <div className="flex items-center gap-3 text-rose-400">
              <AlertTriangle className="w-6 h-6" />
              <h3 className="text-base font-bold text-slate-100">Revoke Audit Report</h3>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Revoking <strong className="text-indigo-300 font-mono">{revokingId}</strong> will invalidate third-party verification queries. This action is recorded in the immutable audit log.
            </p>
            <div className="space-y-1.5">
              <label className="block text-xs font-semibold text-slate-300">
                Reason for Revocation
              </label>
              <textarea
                value={revocationReason}
                onChange={e => setRevocationReason(e.target.value)}
                placeholder="e.g. Discovered subsequent evidence discrepancy or administrative correction..."
                rows={3}
                className="w-full bg-slate-950 border border-slate-800 focus:border-rose-500 focus:ring-1 focus:ring-rose-500 rounded-lg p-2.5 text-xs text-slate-100 placeholder-slate-600"
              />
            </div>
            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => {
                  setRevokingId(null);
                  setRevocationReason('');
                }}
                disabled={revoking}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => handleRevoke(revokingId)}
                disabled={revoking || !revocationReason.trim()}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white text-xs font-semibold rounded-lg transition-colors flex items-center gap-1.5 shadow"
              >
                {revoking ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Ban className="w-3.5 h-3.5" />}
                Confirm Revocation
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
