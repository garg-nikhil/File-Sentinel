import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  HelpCircle,
  Play,
  Download,
  FileSpreadsheet,
  FileCode,
  FileText,
  Search,
  Filter,
  RefreshCw,
  Building2,
  Calendar,
  AlertOctagon,
  ChevronRight,
  Sparkles,
  Users,
  UserCheck,
  Fingerprint,
  Link,
  UserX
} from 'lucide-react';
import { api } from '../../services/api';
import { AuditDetailDrawer } from './AuditDetailDrawer';

export const AuditComplianceView: React.FC<{ recentScanId?: string | null }> = ({ recentScanId }) => {
  const [sessions, setSessions] = useState<any[]>([]);
  const [activeSession, setActiveSession] = useState<any | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [scanning, setScanning] = useState<boolean>(false);
  const [auditErrorForScan, setAuditErrorForScan] = useState<string | null>(null);

  // Run form controls
  const [auditDate, setAuditDate] = useState<string>(() => new Date().toISOString().split('T')[0]);
  const [agencyName, setAgencyName] = useState<string>('');
  const [scanRoots, setScanRoots] = useState<string[]>(['']);

  // Filters & Tabs
  const [activeTab, setActiveTab] = useState<'checklist' | 'categories' | 'gaps' | 'entities' | 'history'>('checklist');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  // Drawer modal state
  const [selectedParamResult, setSelectedParamResult] = useState<any | null>(null);
  const [evidenceGaps, setEvidenceGaps] = useState<any[]>([]);

  useEffect(() => {
    loadAuditSessions();
  }, [recentScanId]);

  const loadAuditSessions = async () => {
    setLoading(true);
    setAuditErrorForScan(null);
    try {
      const data = await api.getAuditSessions();
      setSessions(data || []);
      
      let targetSession = null;
      if (recentScanId) {
        targetSession = data?.find(s => s.scan_id === recentScanId);
      }
      
      if (targetSession) {
        loadSessionDetail(targetSession.audit_id);
      } else if (recentScanId) {
        setAuditErrorForScan(recentScanId);
      } else if (data && data.length > 0) {
        // Load the latest session by default
        loadSessionDetail(data[0].audit_id);
      } else {
        setActiveSession(null);
      }
    } catch (err) {
      console.error('Failed loading audit sessions:', err);
    } finally {
      setLoading(false);
    }
  };

  const retryAudit = async () => {
    if (!auditErrorForScan) return;
    setScanning(true);
    try {
      const session = await api.runAuditScan({
        scan_id: auditErrorForScan,
        audit_date: auditDate || new Date().toISOString().split('T')[0],
        agency_name: agencyName.trim() || 'Telecalling & Collection Agency',
        auditor_name: 'Automated Compliance Inspector'
      });
      setAuditErrorForScan(null);
      await loadAuditSessions();
      if (session && session.audit_id) {
        await loadSessionDetail(session.audit_id);
      }
    } catch (err: any) {
      console.error('Retry failed:', err);
      alert(`Failed to retry audit evaluation: ${err.message || 'Error'}`);
    } finally {
      setScanning(false);
    }
  };

  const loadSessionDetail = async (auditId: string) => {
    try {
      const session = await api.getAuditSessionDetail(auditId);
      setActiveSession(session);
      const gaps = await api.getEvidenceGaps(auditId);
      setEvidenceGaps(gaps || []);
    } catch (err) {
      console.error('Error loading audit session detail:', err);
    }
  };

  const handleRunAuditScan = async () => {
    if (scanRoots.filter(r => r.trim()).length === 0 && !recentScanId) {
      alert('Please enter a target directory path or run a file scan first.');
      return;
    }
    setScanning(true);
    setAuditErrorForScan(null);
    try {
      const newSession = await api.runAuditScan({
        scan_roots: scanRoots.filter(r => r.trim()),
        scan_id: recentScanId || undefined,
        audit_date: auditDate || new Date().toISOString().split('T')[0],
        agency_name: agencyName.trim() || 'Telecalling & Collection Agency',
        auditor_name: 'Automated Compliance Engine'
      });
      await loadAuditSessions();
      if (newSession && newSession.audit_id) {
        await loadSessionDetail(newSession.audit_id);
      }
    } catch (err: any) {
      alert(`Audit scan failed: ${err.message}`);
    } finally {
      setScanning(false);
    }
  };

  const renderStatusBadge = (st: string) => {
    switch (st) {
      case 'PASS':
        return <span className="px-2.5 py-0.5 bg-emerald-100 text-emerald-800 dark:bg-emerald-950/80 dark:text-emerald-300 text-xs font-bold rounded-full inline-flex items-center gap-1 border border-emerald-300 dark:border-emerald-800"><CheckCircle2 className="w-3.5 h-3.5" /> PASS</span>;
      case 'FAIL':
        return <span className="px-2.5 py-0.5 bg-rose-100 text-rose-800 dark:bg-rose-950/80 dark:text-rose-300 text-xs font-bold rounded-full inline-flex items-center gap-1 border border-rose-300 dark:border-rose-800"><XCircle className="w-3.5 h-3.5" /> FAIL</span>;
      case 'REVIEW':
        return <span className="px-2.5 py-0.5 bg-amber-100 text-amber-800 dark:bg-amber-950/80 dark:text-amber-300 text-xs font-bold rounded-full inline-flex items-center gap-1 border border-amber-300 dark:border-amber-800"><AlertTriangle className="w-3.5 h-3.5" /> REVIEW</span>;
      case 'EVIDENCE_NOT_FOUND':
        return <span className="px-2.5 py-0.5 bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-300 text-xs font-bold rounded-full inline-flex items-center gap-1 border border-slate-300 dark:border-slate-700"><HelpCircle className="w-3.5 h-3.5" /> NOT FOUND</span>;
      default:
        return <span className="px-2.5 py-0.5 bg-slate-100 text-slate-800 text-xs font-bold rounded-full">{st}</span>;
    }
  };

  const renderOverallBadge = (st: string) => {
    switch (st) {
      case 'FATAL_FAILURE':
        return <span className="px-3 py-1.5 bg-rose-600 text-white font-extrabold text-xs tracking-wider uppercase rounded-lg shadow inline-flex items-center gap-1.5"><AlertOctagon className="w-4 h-4" /> 🔴 FATAL FAILURE</span>;
      case 'COMPLIANT':
        return <span className="px-3 py-1.5 bg-emerald-600 text-white font-extrabold text-xs tracking-wider uppercase rounded-lg shadow inline-flex items-center gap-1.5"><ShieldCheck className="w-4 h-4" /> 🟢 COMPLIANT</span>;
      case 'NEEDS_REVIEW':
        return <span className="px-3 py-1.5 bg-amber-500 text-white font-extrabold text-xs tracking-wider uppercase rounded-lg shadow inline-flex items-center gap-1.5"><AlertTriangle className="w-4 h-4" /> 🟠 NEEDS AUDITOR REVIEW</span>;
      default:
        return <span className="px-3 py-1.5 bg-slate-600 text-white font-extrabold text-xs tracking-wider uppercase rounded-lg shadow">{st}</span>;
    }
  };

  // Filter parameter results
  const parameterResults = activeSession?.parameter_results || [];
  const filteredResults = parameterResults.filter((r: any) => {
    const effectiveStatus = r.override ? r.override.new_status : r.status;

    if (categoryFilter !== 'ALL' && r.parameter.category !== categoryFilter) return false;
    if (statusFilter !== 'ALL' && effectiveStatus !== statusFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchId = r.parameter_id.toLowerCase().includes(q);
      const matchTitle = r.parameter.parameter.toLowerCase().includes(q);
      const matchKw = r.parameter.keywords.some((k: string) => k.toLowerCase().includes(q));
      if (!matchId && !matchTitle && !matchKw) return false;
    }
    return true;
  });

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 bg-indigo-600 text-white rounded-lg shadow">
              <ShieldCheck className="w-6 h-6" />
            </span>
            <div>
              <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">Audit Evidence & Compliance Engine</h1>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                AI-Assisted Evidence Verification, Structured Parameter Mapping & Regulatory Scoring
              </p>
            </div>
          </div>
        </div>

        {/* Action controls */}
        {activeSession && (
          <div className="flex items-center gap-2 flex-wrap">
            <a
              href={`/api/audit/report/${activeSession.audit_id}/html`}
              target="_blank"
              rel="noreferrer"
              className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 text-xs font-bold rounded-lg transition-colors flex items-center gap-1.5 border border-slate-200 dark:border-slate-700"
            >
              <FileText className="w-3.5 h-3.5 text-indigo-500" /> Printable Report
            </a>
            <a
              href={`/api/audit/report/${activeSession.audit_id}/csv`}
              download
              className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 text-xs font-bold rounded-lg transition-colors flex items-center gap-1.5 border border-slate-200 dark:border-slate-700"
            >
              <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-500" /> Export CSV
            </a>
            <a
              href={`/api/audit/report/${activeSession.audit_id}/json`}
              download
              className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 text-xs font-bold rounded-lg transition-colors flex items-center gap-1.5 border border-slate-200 dark:border-slate-700"
            >
              <FileCode className="w-3.5 h-3.5 text-cyan-500" /> Export JSON
            </a>
            <a
              href={`/api/reports/verify/${activeSession.audit_id}`}
              target="_blank"
              rel="noreferrer"
              className="px-3 py-1.5 bg-indigo-600/10 hover:bg-indigo-600/20 text-indigo-400 text-xs font-bold rounded-lg transition-colors flex items-center gap-1.5 border border-indigo-500/30"
              title="Verify cryptographic SHA-256 integrity signature"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-indigo-400" /> Verify Cryptographic Hash
            </a>
          </div>
        )}
      </div>

      {auditErrorForScan && !activeSession && (
        <div className="p-4 bg-red-950/40 border border-red-500/30 rounded-xl space-y-3">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400 mt-0.5" />
            <div>
              <h3 className="text-red-400 font-bold text-sm">Audit Evaluation Failed</h3>
              <p className="text-slate-300 text-xs mt-1">
                Scan completed, but audit evaluation encountered an error. 
              </p>
            </div>
          </div>
          <button
            onClick={retryAudit}
            disabled={scanning}
            className="bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/50 text-xs font-bold px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
          >
            {scanning ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
            {scanning ? 'Retrying...' : 'Retry Audit Evaluation'}
          </button>
        </div>
      )}

      {/* Audit Configuration / Run Bar */}
      <div className="p-4 bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 rounded-xl space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
          <div>
            <label className="block font-semibold text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
              <Calendar className="w-3.5 h-3.5 text-slate-500" /> Selected Audit Date
            </label>
            <input
              type="date"
              value={auditDate}
              onChange={e => setAuditDate(e.target.value)}
              className="w-full p-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-slate-100 font-semibold"
            />
          </div>

          <div>
            <label className="block font-semibold text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
              <Building2 className="w-3.5 h-3.5 text-slate-500" /> Target Agency
            </label>
            <input
              type="text"
              value={agencyName}
              onChange={e => setAgencyName(e.target.value)}
              placeholder="e.g. Collection & Telecalling Agency"
              className="w-full p-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-slate-100"
            />
          </div>

          <div className="col-span-1 md:col-span-2">
            <div className="flex justify-between items-center mb-1">
              <label className="block font-semibold text-slate-600 dark:text-slate-400">Scan Targets (Multi-Root)</label>
              <button 
                onClick={() => setScanRoots([...scanRoots, ''])}
                className="text-xs text-indigo-600 hover:text-indigo-800 dark:text-indigo-400 flex items-center gap-1 font-semibold"
              >
                + Add Folder
              </button>
            </div>
            <div className="space-y-2">
              {scanRoots.map((root, i) => (
                <div key={i} className="flex gap-2">
                  <input
                    type="text"
                    value={root}
                    onChange={e => {
                      const newRoots = [...scanRoots];
                      newRoots[i] = e.target.value;
                      setScanRoots(newRoots);
                    }}
                    placeholder="e.g. /path/to/evidence/folder"
                    className="flex-1 p-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-slate-100 font-mono text-sm"
                  />
                  {scanRoots.length > 1 && (
                    <button onClick={() => setScanRoots(scanRoots.filter((_, idx) => idx !== i))} className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg">
                      ✕
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>

          <div className="flex items-end">
            <button
              onClick={handleRunAuditScan}
              disabled={scanning || (scanRoots.filter(r => r.trim()).length === 0 && !recentScanId)}
              className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-bold text-xs rounded-lg transition-colors shadow flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {scanning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Scanning Documents & Mapping...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  Run Audit Compliance Scan
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Dashboard Summary Widgets */}
      {activeSession ? (
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          {/* Score & Status Card */}
          <div className="md:col-span-2 p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm flex flex-col justify-between">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-xs font-extrabold text-slate-400 uppercase tracking-wider">Overall Audit Assessment</span>
                <div className="mt-2">
                  {renderOverallBadge(activeSession.overall_status)}
                </div>
              </div>
              <div className="text-right">
                <span className="text-xs text-slate-500">Audit Score</span>
                <div className="text-3xl font-black text-slate-900 dark:text-slate-100">
                  {activeSession.overall_score} <span className="text-base font-normal text-slate-400">/ {activeSession.max_score}</span>
                </div>
              </div>
            </div>

            <div className="mt-4">
              <div className="flex justify-between text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">
                <span>Compliance Score Progress</span>
                <span>{Math.round((activeSession.overall_score / activeSession.max_score) * 100)}%</span>
              </div>
              <div className="w-full h-2.5 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-500 ${
                    activeSession.overall_status === 'FATAL_FAILURE' ? 'bg-rose-500' : 'bg-emerald-500'
                  }`}
                  style={{ width: `${Math.min(100, (activeSession.overall_score / activeSession.max_score) * 100)}%` }}
                />
              </div>
            </div>
          </div>

          {/* Breakdown Stats */}
          <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm flex flex-col justify-between">
            <span className="text-xs font-bold text-slate-400 uppercase">Passed Parameters</span>
            <div className="text-2xl font-black text-emerald-600 dark:text-emerald-400 my-1">{activeSession.pass_count}</div>
            <span className="text-[11px] text-slate-500">Of {activeSession.total_parameters} total checklist rules</span>
          </div>

          <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm flex flex-col justify-between">
            <span className="text-xs font-bold text-slate-400 uppercase">Review & Missing</span>
            <div className="text-2xl font-black text-amber-600 dark:text-amber-400 my-1">
              {activeSession.review_count + activeSession.not_found_count}
            </div>
            <span className="text-[11px] text-slate-500">{activeSession.review_count} Review / {activeSession.not_found_count} Missing</span>
          </div>

          <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm flex flex-col justify-between">
            <span className="text-xs font-bold text-slate-400 uppercase">Fatal Failures</span>
            <div className="text-2xl font-black text-rose-600 dark:text-rose-400 my-1">
              {activeSession.fatal_failures_count}
            </div>
            <span className="text-[11px] text-rose-500 font-semibold">Zero Tolerance Failures</span>
          </div>
        </div>
      ) : (
        <div className="p-8 text-center bg-slate-50 dark:bg-slate-800/40 rounded-2xl border border-dashed border-slate-300 dark:border-slate-700">
          <p className="text-sm font-semibold text-slate-600 dark:text-slate-400">No active audit session loaded. Click "Run Audit Compliance Scan" above to scan and evaluate.</p>
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
        <div className="flex gap-4">
          <button
            onClick={() => setActiveTab('checklist')}
            className={`pb-3 text-xs font-bold transition-colors border-b-2 ${
              activeTab === 'checklist'
                ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            Checklist Parameters ({parameterResults.length})
          </button>

          <button
            onClick={() => setActiveTab('categories')}
            className={`pb-3 text-xs font-bold transition-colors border-b-2 ${
              activeTab === 'categories'
                ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            Category Scores
          </button>

          <button
            onClick={() => setActiveTab('gaps')}
            className={`pb-3 text-xs font-bold transition-colors border-b-2 ${
              activeTab === 'gaps'
                ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            Evidence Gaps & Remediation ({evidenceGaps.length})
          </button>

          <button
            onClick={() => setActiveTab('entities')}
            className={`pb-3 text-xs font-bold transition-colors border-b-2 inline-flex items-center gap-1.5 ${
              activeTab === 'entities'
                ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            <Users className="w-3.5 h-3.5" />
            Entities & Correlation ({activeSession?.entities?.length || 0})
            {activeSession?.entity_conflicts?.length > 0 && (
              <span className="px-1.5 py-0.2 bg-rose-500 text-white rounded-full text-[10px] font-extrabold animate-pulse">
                {activeSession.entity_conflicts.length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('history')}
            className={`pb-3 text-xs font-bold transition-colors border-b-2 ${
              activeTab === 'history'
                ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            Past Audits ({sessions.length})
          </button>
        </div>
      </div>

      {/* TAB 1: CHECKLIST PARAMETERS TABLE */}
      {activeTab === 'checklist' && (
        <div className="space-y-4">
          {/* Filters Bar */}
          <div className="flex flex-col md:flex-row gap-3 items-center justify-between">
            <div className="relative w-full md:w-80">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Search parameter, ID, keywords..."
                className="w-full text-xs pl-9 pr-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-slate-100"
              />
            </div>

            <div className="flex items-center gap-2 w-full md:w-auto">
              <select
                value={categoryFilter}
                onChange={e => setCategoryFilter(e.target.value)}
                className="text-xs p-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-800 dark:text-slate-200"
              >
                <option value="ALL">All Categories</option>
                <option value="ZERO_TOLERANCE">Category 1: Zero Tolerance</option>
                <option value="GOVERNANCE_COMPLIANCE_INFOSEC">Category 2: Governance & INFOSEC</option>
                <option value="INFRASTRUCTURE_PROCESS_MANAGEMENT">Category 3: Infrastructure & Process</option>
              </select>

              <select
                value={statusFilter}
                onChange={e => setStatusFilter(e.target.value)}
                className="text-xs p-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-800 dark:text-slate-200"
              >
                <option value="ALL">All Statuses</option>
                <option value="PASS">PASS</option>
                <option value="FAIL">FAIL</option>
                <option value="REVIEW">REVIEW</option>
                <option value="EVIDENCE_NOT_FOUND">EVIDENCE NOT FOUND</option>
              </select>
            </div>
          </div>

          {/* Table */}
          <div className="border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-sm bg-white dark:bg-slate-900">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 dark:bg-slate-800/80 border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 font-bold uppercase tracking-wider">
                <tr>
                  <th className="p-3.5">ID</th>
                  <th className="p-3.5">Category</th>
                  <th className="p-3.5">Audit Parameter</th>
                  <th className="p-3.5">Fatal</th>
                  <th className="p-3.5">Status</th>
                  <th className="p-3.5">Score</th>
                  <th className="p-3.5">Evidence File</th>
                  <th className="p-3.5 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                {filteredResults.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="p-8 text-center text-slate-400 font-medium">
                      No audit parameters matched the current filter criteria.
                    </td>
                  </tr>
                ) : (
                  filteredResults.map((r: any) => {
                    const effectiveStatus = r.override ? r.override.new_status : r.status;
                    return (
                      <tr key={r.parameter_id} className="hover:bg-slate-50/80 dark:hover:bg-slate-800/50 transition-colors">
                        <td className="p-3.5 font-bold text-slate-900 dark:text-slate-100">
                          {r.parameter_id}
                        </td>
                        <td className="p-3.5 font-semibold text-slate-500 max-w-[140px] truncate">
                          {r.parameter.category_name}
                        </td>
                        <td className="p-3.5 font-medium text-slate-800 dark:text-slate-200 max-w-xs">
                          {r.parameter.parameter}
                        </td>
                        <td className="p-3.5 font-bold">
                          {r.fatal ? (
                            <span className="text-rose-600 dark:text-rose-400">YES</span>
                          ) : (
                            <span className="text-slate-400">NO</span>
                          )}
                        </td>
                        <td className="p-3.5">
                          {renderStatusBadge(effectiveStatus)}
                          {r.override && (
                            <span className="ml-1 text-[10px] text-cyan-600 font-bold" title="Overridden by auditor">
                              [Edited]
                            </span>
                          )}
                        </td>
                        <td className="p-3.5 font-semibold text-slate-700 dark:text-slate-300">
                          {r.score_earned} / {r.max_score}
                        </td>
                        <td className="p-3.5 text-slate-600 dark:text-slate-400 max-w-[150px] truncate">
                          {r.evidence && r.evidence.length > 0 ? (
                            <span className="px-2 py-0.5 bg-slate-100 dark:bg-slate-800 rounded font-mono text-[11px] text-slate-700 dark:text-slate-300">
                              📄 {r.evidence[0].filename}
                            </span>
                          ) : (
                            <span className="text-slate-400 italic">No file found</span>
                          )}
                        </td>
                        <td className="p-3.5 text-right">
                          <button
                            onClick={() => setSelectedParamResult(r)}
                            className="px-2.5 py-1 bg-indigo-50 dark:bg-indigo-950 hover:bg-indigo-100 text-indigo-700 dark:text-indigo-300 font-bold rounded-lg transition-colors inline-flex items-center gap-1"
                          >
                            Details <ChevronRight className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: CATEGORY SCORES */}
      {activeTab === 'categories' && (
        !activeSession ? (
          <div className="p-8 text-center bg-white dark:bg-slate-900 rounded-2xl border border-dashed border-slate-300 dark:border-slate-700 text-slate-400 text-xs">
            No active audit session loaded. Run an audit compliance scan to view category scores.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {Object.entries(activeSession.category_scores || {}).map(([key, cat]: [string, any]) => (
              <div key={key} className="p-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm flex flex-col justify-between space-y-4">
                <div>
                  <span className="text-xs font-extrabold text-slate-400 uppercase tracking-wider">
                    {key === 'ZERO_TOLERANCE' ? 'Category 1' : key === 'GOVERNANCE_COMPLIANCE_INFOSEC' ? 'Category 2' : 'Category 3'}
                  </span>
                  <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 mt-1">
                    {key === 'ZERO_TOLERANCE' ? 'Regulatory and Operational Integrity' : key === 'GOVERNANCE_COMPLIANCE_INFOSEC' ? 'Governance, Compliance & INFOSEC' : 'Infrastructure & Process Management'}
                  </h3>
                </div>

                <div>
                  <div className="flex justify-between items-baseline mb-2">
                    <span className="text-2xl font-black text-slate-900 dark:text-slate-100">
                      {cat.earned} <span className="text-sm font-normal text-slate-400">/ {cat.max} pts</span>
                    </span>
                    <span className={`px-2.5 py-0.5 text-xs font-bold rounded-full ${
                      cat.status === 'PASS' ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300' : 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                    }`}>
                      {cat.status}
                    </span>
                  </div>

                  <div className="w-full h-2 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-indigo-600 transition-all duration-500"
                      style={{ width: `${Math.min(100, (cat.earned / cat.max) * 100)}%` }}
                    />
                  </div>
                </div>

                <div className="text-xs text-slate-500 pt-2 border-t border-slate-100 dark:border-slate-800">
                  Fatal Requirements: {key === 'ZERO_TOLERANCE' ? 'YES (Critical)' : 'NO'}
                </div>
              </div>
            ))}
          </div>
        )
      )}

      {/* TAB 3: EVIDENCE GAPS & REMEDIATION */}
      {activeTab === 'gaps' && (
        <div className="space-y-4">
          <div className="p-4 bg-rose-50 dark:bg-rose-950/30 border border-rose-200 dark:border-rose-900 rounded-xl text-xs text-rose-900 dark:text-rose-300">
            <strong>Evidence Gaps & Actionable Remediation:</strong> Below are parameters that failed or required missing evidence. Address these items to improve your audit score and clear fatal flags.
          </div>

          <div className="space-y-3">
            {evidenceGaps.length === 0 ? (
              <div className="p-8 text-center text-slate-400 text-sm font-medium">
                🎉 No evidence gaps identified! All checklist requirements are satisfied.
              </div>
            ) : (
              evidenceGaps.map((gap: any, idx: number) => (
                <div key={idx} className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl space-y-2 shadow-sm">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 text-[10px] font-extrabold uppercase rounded ${
                        gap.priority === 'HIGH' ? 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300 border border-rose-300 dark:border-rose-800' : 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                      }`}>
                        {gap.priority} PRIORITY
                      </span>
                      <strong className="text-sm font-bold text-slate-900 dark:text-slate-100">{gap.parameter_id}: {gap.parameter_title}</strong>
                    </div>
                    {renderStatusBadge(gap.status)}
                  </div>

                  <div className="text-xs text-slate-600 dark:text-slate-300">
                    <strong>Missing Evidence:</strong> {gap.missing}
                  </div>

                  <div className="p-2.5 bg-slate-50 dark:bg-slate-800/80 rounded-lg text-xs text-slate-800 dark:text-slate-200 border border-slate-200 dark:border-slate-700">
                    💡 <strong>Recommended Action:</strong> {gap.recommended_action}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB 4: ENTITIES & CROSS-PARAMETER CORRELATION */}
      {activeTab === 'entities' && (
        <div className="space-y-6">
          <div className="p-4 bg-indigo-50 dark:bg-indigo-950/40 border border-indigo-200 dark:border-indigo-800 rounded-xl text-xs text-indigo-900 dark:text-indigo-200 flex items-start gap-3">
            <Fingerprint className="w-5 h-5 text-indigo-600 dark:text-indigo-400 shrink-0 mt-0.5" />
            <div>
              <strong className="font-bold">Audit-Session-Level Entity Resolution:</strong>
              <p className="mt-1 text-slate-700 dark:text-slate-300">
                Correlates individuals, field agents, certificates, and agency credentials across the entire audit session (e.g. DRA Certificates, Police Verification slips, and Agency ID badges). Automatically matches name variants and strong identifiers (Agent ID, Employee ID, Cert #), clustering evidence items into unified identity entities while flagging identity mismatches.
              </p>
            </div>
          </div>

          {/* Conflicts Alert if any */}
          {activeSession?.entity_conflicts && activeSession.entity_conflicts.length > 0 && (
            <div className="p-4 bg-rose-50 dark:bg-rose-950/50 border border-rose-300 dark:border-rose-800 rounded-xl space-y-3">
              <div className="flex items-center gap-2 text-rose-800 dark:text-rose-300 font-bold text-xs">
                <AlertOctagon className="w-4 h-4 text-rose-600 dark:text-rose-400" />
                <span>POSSIBLE ENTITY MISMATCH CONFLICTS DETECTED ({activeSession.entity_conflicts.length})</span>
              </div>
              <div className="space-y-2">
                {activeSession.entity_conflicts.map((conflict: any, cidx: number) => (
                  <div key={cidx} className="p-3 bg-white dark:bg-slate-900 border border-rose-200 dark:border-rose-900 rounded-lg text-xs space-y-1.5 shadow-sm">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-rose-700 dark:text-rose-400">
                        {conflict.conflict_type.replace(/_/g, ' ')}
                      </span>
                      <span className={`px-2 py-0.5 text-[10px] font-extrabold uppercase rounded ${
                        conflict.severity === 'FATAL' || conflict.severity === 'HIGH'
                          ? 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300'
                          : 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                      }`}>
                        {conflict.severity} SEVERITY
                      </span>
                    </div>
                    <p className="text-slate-700 dark:text-slate-300">{conflict.description}</p>
                    <div className="text-[11px] text-slate-500 font-mono">
                      Impacted Parameters: {conflict.involved_parameter_ids?.join(', ')}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Resolved Entities List */}
          <div className="space-y-4">
            <h4 className="text-xs font-extrabold uppercase tracking-wider text-slate-400">
              Resolved Individuals & Agent Entities ({activeSession?.entities?.length || 0})
            </h4>

            {(!activeSession?.entities || activeSession.entities.length === 0) ? (
              <div className="p-8 text-center bg-white dark:bg-slate-900 rounded-xl border border-dashed border-slate-300 dark:border-slate-700 text-slate-400 text-xs">
                No distinct person or agent entities extracted from validated evidence in this session.
              </div>
            ) : (
              <div className="grid grid-cols-1 gap-4">
                {activeSession.entities.map((entity: any) => (
                  <div
                    key={entity.entity_id}
                    className="p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm space-y-4"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800/80 pb-3">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-xl bg-indigo-50 dark:bg-indigo-950 border border-indigo-200 dark:border-indigo-800 flex items-center justify-center text-indigo-600 dark:text-indigo-400 font-black text-sm">
                          <UserCheck className="w-5 h-5" />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                              {entity.name}
                            </h3>
                            <span className="px-2 py-0.5 bg-slate-100 dark:bg-slate-800 font-mono text-[10px] text-slate-500 rounded">
                              Normalized: {entity.normalized_name}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-400 font-mono">Entity ID: {entity.entity_id}</p>
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        {entity.status === 'CONSISTENT' ? (
                          <span className="px-2.5 py-1 bg-emerald-100 text-emerald-800 dark:bg-emerald-950/80 dark:text-emerald-300 font-bold text-xs rounded-full border border-emerald-300 dark:border-emerald-800 inline-flex items-center gap-1">
                            <CheckCircle2 className="w-3.5 h-3.5" /> CONSISTENT IDENTITY
                          </span>
                        ) : (
                          <span className="px-2.5 py-1 bg-amber-100 text-amber-800 dark:bg-amber-950/80 dark:text-amber-300 font-bold text-xs rounded-full border border-amber-300 dark:border-amber-800 inline-flex items-center gap-1">
                            <AlertTriangle className="w-3.5 h-3.5" /> {entity.status}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Identifiers Badges */}
                    <div className="flex flex-wrap gap-2 text-xs">
                      {entity.agent_id && (
                        <div className="px-2.5 py-1 bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 rounded-lg border border-slate-200 dark:border-slate-700">
                          <span className="text-slate-400 font-medium">Agent ID:</span> <strong className="font-bold">{entity.agent_id}</strong>
                        </div>
                      )}
                      {entity.employee_id && (
                        <div className="px-2.5 py-1 bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 rounded-lg border border-slate-200 dark:border-slate-700">
                          <span className="text-slate-400 font-medium">Employee ID:</span> <strong className="font-bold">{entity.employee_id}</strong>
                        </div>
                      )}
                      {entity.certificate_number && (
                        <div className="px-2.5 py-1 bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 rounded-lg border border-slate-200 dark:border-slate-700">
                          <span className="text-slate-400 font-medium">Certificate / Ack #:</span> <strong className="font-bold">{entity.certificate_number}</strong>
                        </div>
                      )}
                      {entity.email && (
                        <div className="px-2.5 py-1 bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 rounded-lg border border-slate-200 dark:border-slate-700">
                          <span className="text-slate-400 font-medium">Email:</span> <strong className="font-bold">{entity.email}</strong>
                        </div>
                      )}
                      {entity.phone && (
                        <div className="px-2.5 py-1 bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 rounded-lg border border-slate-200 dark:border-slate-700">
                          <span className="text-slate-400 font-medium">Phone:</span> <strong className="font-bold">{entity.phone}</strong>
                        </div>
                      )}
                    </div>

                    {/* Matching Signals */}
                    {entity.matching_signals && entity.matching_signals.length > 0 && (
                      <div className="text-xs text-slate-600 dark:text-slate-400 space-y-1">
                        <span className="font-semibold text-slate-500">Correlation Signals:</span>
                        <div className="flex flex-wrap gap-1.5 mt-0.5">
                          {entity.matching_signals.map((sig: string, sidx: number) => (
                            <span key={sidx} className="px-2 py-0.5 bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 rounded text-[11px] font-medium border border-indigo-100 dark:border-indigo-900">
                              🔗 {sig}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Linked Evidence Files */}
                    <div className="space-y-1.5 pt-2 border-t border-slate-100 dark:border-slate-800/80">
                      <span className="text-xs font-bold text-slate-700 dark:text-slate-300">
                        Linked Cross-Parameter Evidence ({entity.linked_evidence?.length || 0}):
                      </span>
                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 mt-1">
                        {(entity.linked_evidence || []).map((ev: any, eidx: number) => (
                          <div
                            key={eidx}
                            className="p-2.5 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-200 dark:border-slate-700/80 text-xs space-y-1"
                          >
                            <div className="flex items-center justify-between">
                              <span className="font-mono font-bold text-indigo-600 dark:text-indigo-400">
                                {ev.parameter_id || ev.parameterId}
                              </span>
                              <span className="text-[10px] text-emerald-600 dark:text-emerald-400 font-bold">
                                {Math.round((ev.confidence || 0.9) * 100)}% Conf
                              </span>
                            </div>
                            <div className="font-medium text-slate-800 dark:text-slate-200 truncate" title={ev.parameter_title || ev.parameterTitle}>
                              {ev.parameter_title || ev.parameterTitle}
                            </div>
                            <div className="font-mono text-[11px] text-slate-500 truncate" title={ev.filename}>
                              📄 {ev.filename}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 5: PAST AUDITS HISTORY */}
      {activeTab === 'history' && (
        <div className="border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden bg-white dark:bg-slate-900 shadow-sm">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 dark:bg-slate-800/80 border-b border-slate-200 dark:border-slate-800 text-slate-500 font-bold uppercase">
              <tr>
                <th className="p-3.5">Audit ID</th>
                <th className="p-3.5">Audit Date</th>
                <th className="p-3.5">Agency Name</th>
                <th className="p-3.5">Score</th>
                <th className="p-3.5">Status</th>
                <th className="p-3.5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {sessions.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-slate-400 font-medium">
                    No past audit evaluations recorded.
                  </td>
                </tr>
              ) : (
                sessions.map((s: any) => (
                  <tr key={s.audit_id} className="hover:bg-slate-50/80 dark:hover:bg-slate-800/50">
                    <td className="p-3.5 font-bold text-slate-900 dark:text-slate-100">{s.audit_id}</td>
                    <td className="p-3.5 text-slate-600 dark:text-slate-400">{s.audit_date}</td>
                    <td className="p-3.5 font-medium text-slate-800 dark:text-slate-200">{s.agency_name}</td>
                    <td className="p-3.5 font-bold">{s.overall_score} / {s.max_score}</td>
                    <td className="p-3.5">{renderOverallBadge(s.overall_status)}</td>
                    <td className="p-3.5 text-right">
                      <button
                        onClick={() => {
                          loadSessionDetail(s.audit_id);
                          setActiveTab('checklist');
                        }}
                        className="px-2.5 py-1 bg-indigo-50 dark:bg-indigo-950 text-indigo-700 dark:text-indigo-300 font-bold rounded-lg hover:bg-indigo-100"
                      >
                        Load Session
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Detail Drawer Modal */}
      {selectedParamResult && activeSession && (
        <AuditDetailDrawer
          parameterResult={selectedParamResult}
          auditId={activeSession.audit_id}
          onClose={() => setSelectedParamResult(null)}
          onOverrideSuccess={async () => {
            setSelectedParamResult(null);
            await loadAuditSessions();
            await loadSessionDetail(activeSession.audit_id);
          }}
        />
      )}
    </div>
  );
};
