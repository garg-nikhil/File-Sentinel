import React, { useState, useEffect } from 'react';
import { AppSettings, GovernanceManifest, TelemetryInspectionResult, RetentionPolicy, DataClassificationCategory, ScanSession } from '../types';
import { api } from '../services/api';
import {
  Settings,
  Save,
  RefreshCw,
  CheckCircle2,
  Shield,
  Lock,
  Eye,
  AlertTriangle,
  Database,
  FileText,
  Trash2,
  HelpCircle,
  HardDrive,
  Cpu,
  Terminal,
  ShieldCheck,
  ShieldAlert,
  Server,
  Layers,
  ChevronDown,
  ChevronRight,
  Info,
  Clock,
  Calendar,
  Play,
  Plus,
  Mail,
  Folder
} from 'lucide-react';

export const SettingsView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'privacy_governance' | 'recurring_scan' | 'telemetry_debugger' | 'retention' | 'general'>('privacy_governance');
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [savedMsg, setSavedMsg] = useState(false);
  const [governance, setGovernance] = useState<GovernanceManifest | null>(null);
  const [recentScans, setRecentScans] = useState<ScanSession[]>([]);

  useEffect(() => {
    loadInitialData();
  }, []);

  const loadInitialData = async () => {
    try {
      const [settingsData, govData, scansData] = await Promise.all([
        api.getSettings(),
        api.getPrivacyGovernance().catch(() => null),
        api.getScanHistory().catch(() => [])
      ]);
      setSettings(settingsData);
      if (govData) setGovernance(govData);
      if (scansData) setRecentScans(scansData);
    } catch (e) {
      console.error('Failed to load settings view data:', e);
    }
  };

  const handleSave = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!settings) return;

    try {
      setSaving(true);
      await api.updateSettings(settings);
      setSavedMsg(true);
      setTimeout(() => setSavedMsg(false), 3000);
    } catch (e) {
      console.error(e);
    } finally {
      setSaving(false);
    }
  };

  if (!settings) {
    return <div className="p-8 text-center text-slate-400 font-mono animate-pulse">Loading privacy & governance settings...</div>;
  }

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-emerald-400" />
            <h1 className="text-xl font-bold text-slate-100">Privacy & Data Governance Settings</h1>
            <span className="bg-emerald-950/80 text-emerald-400 text-[11px] font-mono font-semibold px-2.5 py-0.5 rounded-full border border-emerald-800">
              LOCAL-FIRST ARCHITECTURE
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Enforces the foundational principle: <span className="text-slate-200 font-mono font-semibold">SCAN LOCAL. STORE DOCUMENTS LOCAL. TRANSMIT MINIMUM METADATA.</span>
          </p>
        </div>

        <div className="flex items-center gap-3">
          {savedMsg && (
            <span className="text-xs text-emerald-400 font-mono flex items-center gap-1.5 bg-emerald-950/50 px-3 py-1.5 rounded-lg border border-emerald-800">
              <CheckCircle2 className="w-4 h-4" />
              Settings Saved
            </span>
          )}
          <button
            onClick={() => handleSave()}
            disabled={saving}
            className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-4 py-2 rounded-lg text-xs flex items-center gap-2 transition-colors disabled:opacity-50"
          >
            <Save className="w-4 h-4" />
            {saving ? 'Saving...' : 'Save Configuration'}
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-1">
        <button
          onClick={() => setActiveTab('privacy_governance')}
          className={`px-4 py-2 text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 ${
            activeTab === 'privacy_governance'
              ? 'bg-slate-800 text-emerald-400 border-t-2 border-emerald-500'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Lock className="w-3.5 h-3.5" />
          Privacy Controls & Classification
        </button>
        <button
          onClick={() => setActiveTab('recurring_scan')}
          className={`px-4 py-2 text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 ${
            activeTab === 'recurring_scan'
              ? 'bg-slate-800 text-indigo-400 border-t-2 border-indigo-500'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Clock className="w-3.5 h-3.5 text-indigo-400" />
          Automated Scan Scheduler
        </button>
        <button
          onClick={() => setActiveTab('telemetry_debugger')}
          className={`px-4 py-2 text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 ${
            activeTab === 'telemetry_debugger'
              ? 'bg-slate-800 text-emerald-400 border-t-2 border-emerald-500'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          Telemetry Debugger (Payload Inspector)
        </button>
        <button
          onClick={() => setActiveTab('retention')}
          className={`px-4 py-2 text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 ${
            activeTab === 'retention'
              ? 'bg-slate-800 text-emerald-400 border-t-2 border-emerald-500'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Database className="w-3.5 h-3.5" />
          Data Retention & Local Durability
        </button>
        <button
          onClick={() => setActiveTab('general')}
          className={`px-4 py-2 text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 ${
            activeTab === 'general'
              ? 'bg-slate-800 text-emerald-400 border-t-2 border-emerald-500'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Settings className="w-3.5 h-3.5" />
          General Engine Settings
        </button>
      </div>

      {/* TAB 1: PRIVACY CONTROLS & DATA CLASSIFICATION */}
      {activeTab === 'privacy_governance' && (
        <div className="space-y-6">
          {/* Mandatory 4-Pillar Privacy Settings Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-emerald-400" />
                  Primary Privacy Controls & Boundary Guardrails
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Direct hardware-level controls governing what stays on this machine and what transmits.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* 1. Document Content (Fixed LOCAL ONLY) */}
              <div className="bg-slate-950 border border-emerald-900/60 rounded-xl p-4 flex flex-col justify-between">
                <div className="flex items-start justify-between">
                  <div>
                    <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider block">
                      Document Content
                    </span>
                    <p className="text-xs text-slate-400 mt-1">
                      Raw file bytes, extracted full-text, OCR streams, and PII context.
                    </p>
                  </div>
                  <div className="flex items-center gap-1.5 bg-emerald-950 text-emerald-400 border border-emerald-700/60 px-2.5 py-1 rounded-md text-xs font-bold font-mono">
                    <Lock className="w-3.5 h-3.5" />
                    LOCAL ONLY
                  </div>
                </div>
                <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center gap-2 text-[11px] text-emerald-400/90 font-mono">
                  <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
                  Guaranteed: Files are never uploaded without explicit manual user confirmation.
                </div>
              </div>

              {/* 2. Scan Statistics (ON/OFF) */}
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                <div className="flex items-start justify-between">
                  <div>
                    <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider block">
                      Scan Statistics
                    </span>
                    <p className="text-xs text-slate-400 mt-1">
                      Transmits aggregate scan counts, duration, and score percentages for vendor dashboards.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setSettings({ ...settings, telemetryEnabled: !settings.telemetryEnabled })}
                    className={`px-3 py-1 rounded-md text-xs font-bold font-mono transition-colors ${
                      settings.telemetryEnabled
                        ? 'bg-emerald-900/80 text-emerald-300 border border-emerald-600'
                        : 'bg-slate-800 text-slate-400 border border-slate-700'
                    }`}
                  >
                    {settings.telemetryEnabled ? 'ON' : 'OFF'}
                  </button>
                </div>
                <div className="mt-3 pt-3 border-t border-slate-800/80 text-[11px] text-slate-400 font-mono">
                  {settings.telemetryEnabled ? '✓ Minimal aggregate metrics active' : '✕ Telemetry disabled: Scan stats kept local'}
                </div>
              </div>

              {/* 3. Crash Diagnostics (ON/OFF) */}
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                <div className="flex items-start justify-between">
                  <div>
                    <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider block">
                      Crash Diagnostics
                    </span>
                    <p className="text-xs text-slate-400 mt-1">
                      Anonymous exception traces to diagnose engine failures. Excludes paths and document data.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setSettings({ ...settings, crashReportingEnabled: !settings.crashReportingEnabled })}
                    className={`px-3 py-1 rounded-md text-xs font-bold font-mono transition-colors ${
                      settings.crashReportingEnabled
                        ? 'bg-emerald-900/80 text-emerald-300 border border-emerald-600'
                        : 'bg-slate-800 text-slate-400 border border-slate-700'
                    }`}
                  >
                    {settings.crashReportingEnabled ? 'ON' : 'OFF'}
                  </button>
                </div>
                <div className="mt-3 pt-3 border-t border-slate-800/80 text-[11px] text-slate-400 font-mono">
                  {settings.crashReportingEnabled ? '✓ Anonymous engine stack traces enabled' : '✕ Crash diagnostics disabled'}
                </div>
              </div>

              {/* 4. Cloud Evidence Backup (ON/OFF) */}
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                <div className="flex items-start justify-between">
                  <div>
                    <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider block">
                      Cloud Evidence Backup
                    </span>
                    <p className="text-xs text-slate-400 mt-1">
                      Allows manual operator-triggered staging of specific verified evidence items to cloud storage.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setSettings({ ...settings, cloudUploadEnabled: !settings.cloudUploadEnabled })}
                    className={`px-3 py-1 rounded-md text-xs font-bold font-mono transition-colors ${
                      settings.cloudUploadEnabled
                        ? 'bg-emerald-900/80 text-emerald-300 border border-emerald-600'
                        : 'bg-slate-800 text-slate-400 border border-slate-700'
                    }`}
                  >
                    {settings.cloudUploadEnabled ? 'ON' : 'OFF'}
                  </button>
                </div>
                <div className="mt-3 pt-3 border-t border-slate-800/80 text-[11px] text-slate-400 font-mono">
                  {settings.cloudUploadEnabled ? '✓ Opt-in manual cloud staging available' : '✕ Cloud staging disabled (Pure offline storage)'}
                </div>
              </div>
            </div>

            {/* Additional Safety Toggles */}
            <div className="pt-4 border-t border-slate-800 space-y-3">
              <div className="flex items-center justify-between p-3 bg-slate-950 rounded-lg border border-slate-800/80">
                <div>
                  <span className="text-xs font-semibold text-slate-200 block">Debug Filename Telemetry (Opt-In Only)</span>
                  <span className="text-[11px] text-slate-400">
                    Includes base filenames in telemetry. <span className="text-amber-400">Warning: Filenames may contain customer names or IDs. Keep OFF unless debugging.</span>
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={settings.debugFilenamesEnabled ?? false}
                  onChange={e => setSettings({ ...settings, debugFilenamesEnabled: e.target.checked })}
                  className="w-4 h-4 accent-amber-500 rounded cursor-pointer"
                />
              </div>

              <div className="flex items-center justify-between p-3 bg-slate-950 rounded-lg border border-slate-800/80">
                <div>
                  <span className="text-xs font-semibold text-slate-200 block">Mask Sensitive Preview Snippets</span>
                  <span className="text-[11px] text-slate-400">Redacts matched credentials, PAN, Aadhaar, and phone numbers in local UI previews.</span>
                </div>
                <input
                  type="checkbox"
                  checked={settings.redactSensitivePreview ?? true}
                  onChange={e => setSettings({ ...settings, redactSensitivePreview: e.target.checked })}
                  className="w-4 h-4 accent-emerald-500 rounded cursor-pointer"
                />
              </div>
            </div>
          </div>

          {/* Formal Data Classification Matrix */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
            <div>
              <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Layers className="w-4 h-4 text-emerald-400" />
                Formal Data Classification & Transmission Model
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Every data field in FileSentinel is mapped to a strict classification boundary.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Category A Card */}
              <div className="bg-slate-950 border border-red-900/40 rounded-xl p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-red-400 uppercase tracking-wider font-mono">Category A</span>
                  <span className="bg-red-950 text-red-400 text-[10px] font-bold px-2 py-0.5 rounded border border-red-800">
                    NEVER TRANSMITTED
                  </span>
                </div>
                <h3 className="text-sm font-semibold text-slate-100">Local-Only Sensitive Data</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Data processed strictly in local RAM and stored only in local SQLite. Excluded from all network traffic.
                </p>
                <div className="pt-2 text-[11px] font-mono text-slate-300 space-y-1">
                  <div className="flex items-center gap-1.5"><Lock className="w-3 h-3 text-red-400" /> Document Contents & Binary Files</div>
                  <div className="flex items-center gap-1.5"><Lock className="w-3 h-3 text-red-400" /> Extracted Full-Text & OCR Streams</div>
                  <div className="flex items-center gap-1.5"><Lock className="w-3 h-3 text-red-400" /> PII, Names, PAN, Aadhaar, GSTIN</div>
                  <div className="flex items-center gap-1.5"><Lock className="w-3 h-3 text-red-400" /> Employee IDs, Phones, Emails</div>
                  <div className="flex items-center gap-1.5"><Lock className="w-3 h-3 text-red-400" /> Certificate Numbers & Evidence Snippets</div>
                </div>
              </div>

              {/* Category B Card */}
              <div className="bg-slate-950 border border-emerald-900/40 rounded-xl p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider font-mono">Category B</span>
                  <span className="bg-emerald-950 text-emerald-400 text-[10px] font-bold px-2 py-0.5 rounded border border-emerald-800">
                    AGGREGATE TELEMETRY
                  </span>
                </div>
                <h3 className="text-sm font-semibold text-slate-100">Telemetry-Safe Metadata</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Minimal non-identifying operational counters sent when telemetry is toggled ON for license compliance.
                </p>
                <div className="pt-2 text-[11px] font-mono text-slate-300 space-y-1">
                  <div className="flex items-center gap-1.5"><ShieldCheck className="w-3 h-3 text-emerald-400" /> Scan ID, Tenant ID, Device ID</div>
                  <div className="flex items-center gap-1.5"><ShieldCheck className="w-3 h-3 text-emerald-400" /> Start/End Timestamps & Duration</div>
                  <div className="flex items-center gap-1.5"><ShieldCheck className="w-3 h-3 text-emerald-400" /> Total Discovered & Processed Counts</div>
                  <div className="flex items-center gap-1.5"><ShieldCheck className="w-3 h-3 text-emerald-400" /> Compliance Score & Risk Severity Totals</div>
                  <div className="flex items-center gap-1.5"><ShieldCheck className="w-3 h-3 text-emerald-400" /> Software & Checklist Release Versions</div>
                </div>
              </div>

              {/* Category C Card */}
              <div className="bg-slate-950 border border-indigo-900/40 rounded-xl p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-indigo-400 uppercase tracking-wider font-mono">Category C</span>
                  <span className="bg-indigo-950 text-indigo-400 text-[10px] font-bold px-2 py-0.5 rounded border border-indigo-800">
                    MANUAL ACTION ONLY
                  </span>
                </div>
                <h3 className="text-sm font-semibold text-slate-100">Optional Cloud Evidence</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Artifacts explicitly selected by an authorized compliance auditor and uploaded with cryptographic SHA-256 verification.
                </p>
                <div className="pt-2 text-[11px] font-mono text-slate-300 space-y-1">
                  <div className="flex items-center gap-1.5"><HardDrive className="w-3 h-3 text-indigo-400" /> User-Selected Evidence PDF</div>
                  <div className="flex items-center gap-1.5"><HardDrive className="w-3 h-3 text-indigo-400" /> Cryptographic SHA-256 Checksum</div>
                  <div className="flex items-center gap-1.5"><HardDrive className="w-3 h-3 text-indigo-400" /> Verified Cloud Quarantine Vault</div>
                  <div className="flex items-center gap-1.5"><HardDrive className="w-3 h-3 text-indigo-400" /> Non-Destructive Local Retention</div>
                </div>
              </div>
            </div>

            {/* Regulatory Support Disclaimer */}
            <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 text-xs text-slate-400 leading-relaxed flex items-start gap-3">
              <Info className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
              <div>
                <span className="text-slate-200 font-semibold block mb-0.5">Regulatory & Compliance Support Statement</span>
                FileSentinel is engineered to support organizational compliance with data protection principles, including the Digital Personal Data Protection (DPDP) Act 2023, Information Technology Act 2000, and GDPR data minimization tenets. The software provides architectural isolation and technical controls to assist your organization's legal compliance posture, but does not constitute an automatic or official regulatory certification.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: AUTOMATED RECURRING SCAN SCHEDULER */}
      {activeTab === 'recurring_scan' && (
        <RecurringScanSchedulerCard settings={settings} setSettings={setSettings} onSave={handleSave} />
      )}

      {/* TAB 3: TELEMETRY DEBUGGER / PAYLOAD INSPECTOR */}
      {activeTab === 'telemetry_debugger' && (
        <TelemetryDebuggerCard recentScans={recentScans} />
      )}

      {/* TAB 3: DATA RETENTION & LOCAL DURABILITY */}
      {activeTab === 'retention' && (
        <DataRetentionCard />
      )}

      {/* TAB 4: GENERAL ENGINE SETTINGS */}
      {activeTab === 'general' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Settings className="w-4 h-4 text-emerald-400" />
              Static Analyzer Limits & Gemini AI Preferences
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Tune local filesystem boundaries and AI assistant depth.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase mb-2">
                Max File Size Limit (MB)
              </label>
              <input
                type="number"
                value={settings.maxFileSizeMB}
                onChange={e => setSettings({ ...settings, maxFileSizeMB: parseInt(e.target.value) || 10 })}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-sm font-mono text-slate-100 focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase mb-2">
                Max Directory Recursive Depth
              </label>
              <input
                type="number"
                value={settings.maxScanDepth}
                onChange={e => setSettings({ ...settings, maxScanDepth: parseInt(e.target.value) || 5 })}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-sm font-mono text-slate-100 focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>

          <div className="space-y-4 pt-4 border-t border-slate-800/80">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-sm font-semibold text-slate-200 block">Gemini AI Semantic Evaluation</span>
                <span className="text-xs text-slate-400">Allow server-side Gemini 3.6 Flash calls for document risk classification and summaries.</span>
              </div>
              <input
                type="checkbox"
                checked={settings.aiEnabled}
                onChange={e => setSettings({ ...settings, aiEnabled: e.target.checked })}
                className="w-4 h-4 accent-emerald-500 rounded cursor-pointer"
              />
            </div>

            {settings.aiEnabled && (
              <div className="flex items-center justify-between pl-4 border-l-2 border-slate-700">
                <div>
                  <span className="text-sm font-semibold text-slate-200 block">AI Evidence Assistance Privacy Mode</span>
                  <span className="text-xs text-slate-400">Controls how much evidence context is shared with the Gemini AI.</span>
                </div>
                <select
                  value={settings.aiPrivacyMode || 'OFF'}
                  onChange={e => setSettings({ ...settings, aiPrivacyMode: e.target.value as 'OFF' | 'REDACTED_SNIPPETS' | 'FULL_TEXT' })}
                  className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded px-2.5 py-1.5 outline-none focus:border-emerald-500"
                >
                  <option value="OFF">OFF (No context shared)</option>
                  <option value="REDACTED_SNIPPETS">REDACTED SNIPPETS (Safe snippets only)</option>
                  <option value="FULL_TEXT">FULL TEXT (Unredacted document content)</option>
                </select>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Offline Telemetry Queue Status Widget */}
      <TelemetryQueueCard />
    </div>
  );
};

/* --- TELEMETRY DEBUGGER COMPONENT --- */
const TelemetryDebuggerCard: React.FC<{ recentScans: ScanSession[] }> = ({ recentScans }) => {
  const [selectedScanId, setSelectedScanId] = useState<string>('');
  const [inspection, setInspection] = useState<TelemetryInspectionResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [inspectError, setInspectError] = useState<string | null>(null);
  const [showJsonRaw, setShowJsonRaw] = useState(false);

  useEffect(() => {
    if (recentScans.length > 0 && !selectedScanId) {
      setSelectedScanId(recentScans[0].scan_id);
    }
  }, [recentScans]);

  const handleInspect = async (scanIdToInspect: string) => {
    if (!scanIdToInspect) return;
    try {
      setLoading(true);
      setInspectError(null);
      const res = await api.getTelemetryInspection(scanIdToInspect);
      setInspection(res);
    } catch (err: any) {
      setInspectError(err.message || 'Failed to inspect scan telemetry');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-emerald-400" />
            Telemetry Payload Inspection & Leakage Verifier
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Transparently preview and audit the exact JSON payload that leaves the machine for any scan session.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={selectedScanId}
            onChange={e => setSelectedScanId(e.target.value)}
            className="bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-2 outline-none font-mono"
          >
            {recentScans.length === 0 ? (
              <option value="">No recent scans</option>
            ) : (
              recentScans.map(s => (
                <option key={s.scan_id} value={s.scan_id}>
                  {s.scan_id.substring(0, 18)}... ({s.total_files} files)
                </option>
              ))
            )}
          </select>

          <button
            onClick={() => handleInspect(selectedScanId)}
            disabled={!selectedScanId || loading}
            className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-4 py-2 rounded-lg text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <Eye className="w-3.5 h-3.5" />
            {loading ? 'Inspecting...' : 'Inspect Payload'}
          </button>
        </div>
      </div>

      {inspectError && (
        <div className="p-3 bg-red-950/50 border border-red-800 text-red-400 text-xs rounded-lg flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {inspectError}
        </div>
      )}

      {inspection && (
        <div className="space-y-6">
          {/* Verdict Banner */}
          <div className={`p-4 rounded-xl border flex flex-col md:flex-row md:items-center md:justify-between gap-4 ${
            inspection.verdict === 'APPROVED_FOR_TRANSMISSION'
              ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-300'
              : 'bg-red-950/40 border-red-800 text-red-300'
          }`}>
            <div className="flex items-center gap-3">
              {inspection.verdict === 'APPROVED_FOR_TRANSMISSION' ? (
                <ShieldCheck className="w-8 h-8 text-emerald-400 shrink-0" />
              ) : (
                <ShieldAlert className="w-8 h-8 text-red-400 shrink-0" />
              )}
              <div>
                <span className="text-xs font-mono font-bold uppercase tracking-wider block">Zero-Leakage Security Verdict</span>
                <span className="text-sm font-bold block">
                  {inspection.verdict === 'APPROVED_FOR_TRANSMISSION'
                    ? 'VERIFIED CLEAN: Zero Category A Sensitive Leaks (Approved for Transmission)'
                    : 'BLOCKED: Sensitive PII or Document Data Detected'}
                </span>
                <span className="text-xs text-slate-400 block mt-0.5">
                  Audited {inspection.total_fields} fields • {inspection.category_a_violations_detected} leaks detected • {inspection.category_b_safe_fields} safe Category B metrics
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowJsonRaw(!showJsonRaw)}
                className="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono px-3 py-1.5 rounded-lg border border-slate-700 transition-colors"
              >
                {showJsonRaw ? 'Show Field Matrix' : 'View Raw JSON'}
              </button>
            </div>
          </div>

          {/* Raw JSON Preview vs Field Audit Table */}
          {showJsonRaw ? (
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 overflow-x-auto">
              <pre className="text-xs font-mono text-emerald-400 leading-relaxed">
                {JSON.stringify(inspection.raw_payload_preview, null, 2)}
              </pre>
            </div>
          ) : (
            <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-800 bg-slate-900/50 flex items-center justify-between">
                <span className="text-xs font-bold text-slate-300 uppercase font-mono">Field-By-Field Data Audit</span>
                <span className="text-[11px] text-slate-400">Inspected at {new Date(inspection.inspection_timestamp).toLocaleTimeString()}</span>
              </div>
              <div className="divide-y divide-slate-800/80 max-h-96 overflow-y-auto font-mono text-xs">
                {inspection.field_audits.map(f => (
                  <div key={f.key} className="p-3 hover:bg-slate-900/40 flex items-start justify-between gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-200">{f.key}</span>
                        <span className="bg-emerald-950 text-emerald-400 text-[10px] px-1.5 py-0.2 rounded border border-emerald-800">
                          {f.classification_label}
                        </span>
                      </div>
                      <span className="text-[11px] text-slate-400 font-sans block">{f.privacy_notes}</span>
                    </div>
                    <div className="text-right">
                      <span className="bg-slate-900 border border-slate-800 px-2 py-1 rounded text-slate-300 text-[11px]">
                        {typeof f.value === 'object' ? JSON.stringify(f.value) : String(f.value)}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

/* --- DATA RETENTION & LOCAL DURABILITY COMPONENT --- */
const DataRetentionCard: React.FC = () => {
  const [retention, setRetention] = useState<RetentionPolicy | null>(null);
  const [selectedDays, setSelectedDays] = useState<number>(90);
  const [autoPurge, setAutoPurge] = useState(true);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [purging, setPurging] = useState(false);
  const [purgeResult, setPurgeResult] = useState<any>(null);
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    loadRetention();
  }, []);

  const loadRetention = async () => {
    try {
      const pol = await api.getRetentionPolicy();
      setRetention(pol);
      setSelectedDays(pol.cloud_metadata_retention_days);
      setAutoPurge(pol.auto_purge_enabled);
    } catch (e) {
      console.error(e);
    }
  };

  const handleUpdatePolicy = async () => {
    try {
      setSavingPolicy(true);
      const res = await api.updateRetentionPolicy({
        cloud_metadata_retention_days: selectedDays,
        auto_purge_enabled: autoPurge
      });
      setRetention(res.policy);
      setMsg('Retention policy updated.');
      setTimeout(() => setMsg(null), 3000);
    } catch (e: any) {
      setMsg(`Error: ${e.message}`);
    } finally {
      setSavingPolicy(false);
    }
  };

  const handlePurgeNow = async () => {
    try {
      setPurging(true);
      const res = await api.purgeExpiredCloudTelemetry();
      setPurgeResult(res);
      loadRetention();
    } catch (e: any) {
      setMsg(`Purge error: ${e.message}`);
    } finally {
      setPurging(false);
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
      <div>
        <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
          <Database className="w-4 h-4 text-emerald-400" />
          Cloud Metadata Retention & Local-First Customer Durability
        </h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Configure how long telemetry metadata is retained in the cloud, with hard guarantees that local data is never destroyed.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Retention Policy Config */}
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="text-xs font-bold text-slate-200 uppercase font-mono tracking-wider">
            Cloud Metadata Retention Window
          </h3>

          <div className="space-y-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Retention Expiration Period</label>
              <select
                value={selectedDays}
                onChange={e => setSelectedDays(parseInt(e.target.value))}
                className="w-full bg-slate-900 border border-slate-700 text-slate-100 rounded-lg p-2 text-xs font-mono outline-none"
              >
                <option value={30}>30 Days (Maximum data minimization)</option>
                <option value={90}>90 Days (Quarterly compliance default)</option>
                <option value={180}>180 Days (Semi-annual audit window)</option>
                <option value={365}>365 Days (1-Year annual compliance)</option>
                <option value={-1}>Indefinite (No automatic cloud purge)</option>
              </select>
            </div>

            <div className="flex items-center justify-between pt-2">
              <span className="text-xs text-slate-300">Automated Background Purge</span>
              <input
                type="checkbox"
                checked={autoPurge}
                onChange={e => setAutoPurge(e.target.checked)}
                className="w-4 h-4 accent-emerald-500 rounded cursor-pointer"
              />
            </div>

            <button
              onClick={handleUpdatePolicy}
              disabled={savingPolicy}
              className="w-full bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium py-2 rounded-lg transition-colors disabled:opacity-50"
            >
              {savingPolicy ? 'Updating...' : 'Save Retention Policy'}
            </button>
          </div>
        </div>

        {/* Local Durability Guarantee Card */}
        <div className="bg-slate-950 border border-emerald-900/50 rounded-xl p-5 space-y-3 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-emerald-400 font-bold text-xs uppercase font-mono">
              <ShieldCheck className="w-4 h-4" />
              Customer Audit Durability Guarantee
            </div>
            <p className="text-xs text-slate-300 mt-2 leading-relaxed">
              FileSentinel guarantees that cloud retention purges or subscription plan expirations <span className="font-semibold text-white">NEVER</span> delete or alter your local SQLite audit history, scan records, or evaluated parameters.
            </p>
          </div>

          <div className="pt-3 border-t border-slate-800/80">
            <button
              onClick={handlePurgeNow}
              disabled={purging}
              className="w-full bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium py-2 rounded-lg flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
            >
              <Trash2 className="w-3.5 h-3.5 text-amber-400" />
              {purging ? 'Purging Expired Cloud Records...' : 'Execute Cloud Telemetry Purge Now'}
            </button>
          </div>
        </div>
      </div>

      {purgeResult && (
        <div className="p-4 bg-emerald-950/30 border border-emerald-800/80 rounded-xl text-xs font-mono space-y-1 text-emerald-300">
          <div className="font-bold flex items-center gap-1.5">
            <CheckCircle2 className="w-4 h-4" /> Cloud Purge Completed Successfully
          </div>
          <div>• Purged cloud telemetry records: {purgeResult.purged_telemetry_records}</div>
          <div>• Purged synced queue records: {purgeResult.purged_queue_records}</div>
          <div className="text-slate-300">• Preserved local SQLite scan sessions: <span className="text-emerald-400 font-bold">{purgeResult.local_scans_preserved}</span> (100% Intact)</div>
          <div className="text-slate-300">• Preserved local compliance audit sessions: <span className="text-emerald-400 font-bold">{purgeResult.local_audit_sessions_preserved}</span> (100% Intact)</div>
        </div>
      )}

      {msg && (
        <div className="text-xs font-mono text-emerald-400 bg-emerald-950/40 p-2.5 rounded-lg border border-emerald-800/50">
          {msg}
        </div>
      )}
    </div>
  );
};

/* --- OFFLINE QUEUE STATUS COMPONENT --- */
const TelemetryQueueCard: React.FC = () => {
  const [queueStatus, setQueueStatus] = useState<{ pending_count: number; synced_count: number; failed_count: number; total_queued: number } | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState<string | null>(null);

  const fetchStatus = async () => {
    try {
      const stats = await api.getTelemetryQueueStatus();
      setQueueStatus(stats);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleFlush = async () => {
    try {
      setSyncing(true);
      setSyncMsg(null);
      const res = await api.flushTelemetryQueue();
      setSyncMsg(`Sync complete: ${res.succeeded ?? 0} uploaded, ${res.failed ?? 0} failed.`);
      fetchStatus();
    } catch (err: any) {
      setSyncMsg(`Sync failed: ${err.message}`);
    } finally {
      setSyncing(false);
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <RefreshCw className={`w-4 h-4 text-emerald-400 ${syncing ? 'animate-spin' : ''}`} />
            Offline Telemetry Queue (Local-First Synchronization)
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Local SQLite queue automatically retains aggregate metrics when offline and synchronizes when connected.
          </p>
        </div>
        <button
          onClick={handleFlush}
          disabled={syncing}
          className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3.5 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin' : ''}`} />
          {syncing ? 'Synchronizing...' : 'Flush & Sync Queue'}
        </button>
      </div>

      <div className="grid grid-cols-3 gap-4 pt-2">
        <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-3">
          <span className="text-[11px] font-mono text-slate-400 block uppercase">Pending in Queue</span>
          <span className="text-lg font-bold font-mono text-amber-400">{queueStatus?.pending_count ?? 0}</span>
        </div>
        <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-3">
          <span className="text-[11px] font-mono text-slate-400 block uppercase">Synchronized</span>
          <span className="text-lg font-bold font-mono text-emerald-400">{queueStatus?.synced_count ?? 0}</span>
        </div>
        <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-3">
          <span className="text-[11px] font-mono text-slate-400 block uppercase">Failed / Retrying</span>
          <span className="text-lg font-bold font-mono text-slate-400">{queueStatus?.failed_count ?? 0}</span>
        </div>
      </div>

      {syncMsg && (
        <div className="text-xs font-mono text-emerald-400 bg-emerald-950/40 border border-emerald-800/50 p-2.5 rounded-lg">
          {syncMsg}
        </div>
      )}
    </div>
  );
};

/* --- AUTOMATED RECURRING SCAN SCHEDULER COMPONENT --- */
const RecurringScanSchedulerCard: React.FC<{
  settings: AppSettings;
  setSettings: React.Dispatch<React.SetStateAction<AppSettings | null>>;
  onSave: () => Promise<void>;
}> = ({ settings, setSettings, onSave }) => {
  const [history, setHistory] = useState<any[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [triggering, setTriggering] = useState(false);
  const [newTargetPath, setNewTargetPath] = useState('');
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  const config = settings.recurringScan || {
    enabled: true,
    frequency: 'DAILY',
    time: '02:00',
    dayOfWeek: 1,
    dayOfMonth: 1,
    targetPaths: ['./storage_bucket', 'backend/uploads'],
    scanTypes: ['SECURITY', 'SECRETS', 'PII', 'DOCUMENT'],
    autoQuarantineCritical: false,
    notifyOnCompletion: true,
    notificationEmail: 'compliance-alerts@organization.internal',
    generateReportOnComplete: true,
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      setLoadingHistory(true);
      const data = await api.getScheduledScanHistory();
      setHistory(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingHistory(false);
    }
  };

  const updateConfig = (updates: Partial<typeof config>) => {
    const updated = { ...config, ...updates };
    setSettings({
      ...settings,
      recurringScan: updated
    });
  };

  const handleAddTargetPath = (pathToAdd: string) => {
    const trimmed = pathToAdd.trim();
    if (!trimmed) return;
    if (config.targetPaths.includes(trimmed)) return;
    updateConfig({ targetPaths: [...config.targetPaths, trimmed] });
    setNewTargetPath('');
  };

  const handleRemoveTargetPath = (index: number) => {
    const updated = [...config.targetPaths];
    updated.splice(index, 1);
    updateConfig({ targetPaths: updated });
  };

  const handleToggleScanType = (type: 'SECURITY' | 'SECRETS' | 'PII' | 'DOCUMENT') => {
    let updated: ('SECURITY' | 'SECRETS' | 'PII' | 'DOCUMENT')[];
    if (config.scanTypes.includes(type)) {
      if (config.scanTypes.length === 1) return;
      updated = config.scanTypes.filter(t => t !== type);
    } else {
      updated = [...config.scanTypes, type];
    }
    updateConfig({ scanTypes: updated });
  };

  const handleTriggerNow = async () => {
    try {
      setTriggering(true);
      setStatusMsg(null);
      const res = await api.triggerScheduledScanNow();
      setStatusMsg(`Manual test run executed successfully. Scan ID: ${res.result.scan_id}`);
      fetchHistory();
      const freshSettings = await api.getSettings();
      setSettings(freshSettings);
    } catch (err: any) {
      setStatusMsg(`Trigger error: ${err.message}`);
    } finally {
      setTriggering(false);
    }
  };

  const formatNextRun = (nextIso?: string) => {
    if (!config.enabled) return 'DISABLED';
    if (!nextIso || nextIso === 'DISABLED') return 'Scheduled for next interval';
    try {
      const date = new Date(nextIso);
      return date.toLocaleString();
    } catch {
      return nextIso;
    }
  };

  return (
    <div className="space-y-6">
      {/* Executive Master Scheduler Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Clock className="w-5 h-5 text-indigo-400" />
              <h2 className="text-base font-bold text-slate-100">Automated Recurring Scan Scheduler</h2>
              <span className={`px-2.5 py-0.5 text-[10px] font-mono font-bold rounded-full uppercase border ${
                config.enabled
                  ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                  : 'bg-slate-800 text-slate-400 border-slate-700'
              }`}>
                {config.enabled ? '● SCHEDULER ACTIVE' : '○ SCHEDULER PAUSED'}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Configures automated background security, compliance, and PII inspection scans across designated filesystem targets.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() => updateConfig({ enabled: !config.enabled })}
              className={`px-3.5 py-2 rounded-lg text-xs font-bold font-mono transition-all flex items-center gap-2 ${
                config.enabled
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-700 hover:bg-emerald-900'
                  : 'bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-700'
              }`}
            >
              <Clock className="w-3.5 h-3.5" />
              {config.enabled ? 'Disable Recurring Scans' : 'Enable Recurring Scans'}
            </button>

            <button
              type="button"
              onClick={handleTriggerNow}
              disabled={triggering}
              className="bg-indigo-600 hover:bg-indigo-500 text-white font-bold px-4 py-2 rounded-lg text-xs flex items-center gap-2 transition-all disabled:opacity-50 shadow-md"
            >
              <Play className={`w-3.5 h-3.5 ${triggering ? 'animate-spin' : ''}`} />
              {triggering ? 'Executing Test Scan...' : 'Run Scheduled Scan Now'}
            </button>

            <button
              type="button"
              onClick={onSave}
              className="bg-emerald-600 hover:bg-emerald-500 text-white font-bold px-4 py-2 rounded-lg text-xs flex items-center gap-2 transition-all shadow-md"
            >
              <Save className="w-3.5 h-3.5" />
              Save Scheduler Config
            </button>
          </div>
        </div>

        {/* Status & Next Run Banner */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
            <span className="text-[10px] font-mono font-bold text-slate-400 uppercase block mb-1">
              Next Automated Execution
            </span>
            <span className="text-sm font-black font-mono text-indigo-400 flex items-center gap-2">
              <Calendar className="w-4 h-4 text-indigo-400" />
              {formatNextRun(config.nextRunTime)}
            </span>
          </div>

          <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
            <span className="text-[10px] font-mono font-bold text-slate-400 uppercase block mb-1">
              Last Run Timestamp & Status
            </span>
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-200">
                {config.lastRunTime ? new Date(config.lastRunTime).toLocaleString() : 'Never Executed'}
              </span>
              <span className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded ${
                config.lastRunStatus === 'SUCCESS'
                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                  : config.lastRunStatus === 'WARNING'
                  ? 'bg-amber-950 text-amber-400 border border-amber-800'
                  : 'bg-slate-800 text-slate-400'
              }`}>
                {config.lastRunStatus || 'IDLE'}
              </span>
            </div>
          </div>

          <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
            <span className="text-[10px] font-mono font-bold text-slate-400 uppercase block mb-1">
              Last Scan Metrics
            </span>
            <span className="text-xs font-mono text-slate-300 block">
              <strong className="text-white">{config.lastRunFilesCount ?? 0}</strong> Files Scanned • <strong className="text-amber-400">{config.lastRunFindingsCount ?? 0}</strong> Findings Flashed
            </span>
          </div>
        </div>

        {statusMsg && (
          <div className="p-3 bg-indigo-950/40 border border-indigo-800/80 rounded-xl text-xs font-mono text-indigo-300 flex items-center justify-between">
            <span>{statusMsg}</span>
            <button onClick={() => setStatusMsg(null)} className="text-slate-400 hover:text-white">✕</button>
          </div>
        )}

        {/* SECTION 1: RECURRING SCHEDULE & FREQUENCY */}
        <div className="space-y-4 pt-2">
          <h3 className="text-xs font-bold text-slate-200 uppercase font-mono tracking-wider flex items-center gap-2">
            <Clock className="w-4 h-4 text-emerald-400" />
            1. Automated Execution Frequency & Timing
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[
              { id: 'DAILY', title: 'Daily Automated Scan', desc: 'Runs every 24 hours at designated local time' },
              { id: 'WEEKLY', title: 'Weekly Automated Scan', desc: 'Runs once per week on selected day' },
              { id: 'MONTHLY', title: 'Monthly Automated Scan', desc: 'Runs once per month on selected calendar date' }
            ].map(f => (
              <button
                key={f.id}
                type="button"
                onClick={() => updateConfig({ frequency: f.id as any })}
                className={`p-4 rounded-xl border text-left transition-all ${
                  config.frequency === f.id
                    ? 'bg-slate-800 border-indigo-500 text-white shadow-lg ring-1 ring-indigo-500/50'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold font-mono text-slate-200">{f.title}</span>
                  {config.frequency === f.id && <CheckCircle2 className="w-4 h-4 text-indigo-400" />}
                </div>
                <p className="text-[11px] text-slate-400">{f.desc}</p>
              </button>
            ))}
          </div>

          <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-slate-400 mb-1.5 font-semibold">
                Scheduled Start Time (Local 24-Hour)
              </label>
              <select
                value={config.time || '02:00'}
                onChange={e => updateConfig({ time: e.target.value })}
                className="w-full bg-slate-900 border border-slate-700 text-slate-100 rounded-lg p-2 text-xs font-mono outline-none focus:border-indigo-500"
              >
                <option value="00:00">00:00 Midnight (Off-peak)</option>
                <option value="02:00">02:00 AM (Recommended Default)</option>
                <option value="04:00">04:00 AM (Early Morning)</option>
                <option value="06:00">06:00 AM</option>
                <option value="09:00">09:00 AM (Workday Start)</option>
                <option value="12:00">12:00 PM (Noon)</option>
                <option value="18:00">18:00 PM (Workday End)</option>
                <option value="22:00">22:00 PM (Nightly Audit)</option>
              </select>
            </div>

            {config.frequency === 'WEEKLY' && (
              <div>
                <label className="block text-xs text-slate-400 mb-1.5 font-semibold">
                  Day of Week
                </label>
                <div className="flex items-center gap-1.5">
                  {[
                    { day: 1, label: 'Mon' },
                    { day: 2, label: 'Tue' },
                    { day: 3, label: 'Wed' },
                    { day: 4, label: 'Thu' },
                    { day: 5, label: 'Fri' },
                    { day: 6, label: 'Sat' },
                    { day: 7, label: 'Sun' }
                  ].map(d => (
                    <button
                      key={d.day}
                      type="button"
                      onClick={() => updateConfig({ dayOfWeek: d.day })}
                      className={`flex-1 py-1.5 text-xs font-mono font-bold rounded border transition-all ${
                        config.dayOfWeek === d.day
                          ? 'bg-indigo-600 text-white border-indigo-500'
                          : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-white'
                      }`}
                    >
                      {d.label}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {config.frequency === 'MONTHLY' && (
              <div>
                <label className="block text-xs text-slate-400 mb-1.5 font-semibold">
                  Day of Month
                </label>
                <select
                  value={config.dayOfMonth || 1}
                  onChange={e => updateConfig({ dayOfMonth: parseInt(e.target.value) })}
                  className="w-full bg-slate-900 border border-slate-700 text-slate-100 rounded-lg p-2 text-xs font-mono outline-none focus:border-indigo-500"
                >
                  <option value={1}>1st of the Month (Monthly Audit)</option>
                  <option value={15}>15th of the Month (Mid-month Check)</option>
                  <option value={28}>28th of the Month (End-of-month Close)</option>
                </select>
              </div>
            )}
          </div>
        </div>

        {/* SECTION 2: TARGET DIRECTORY PATHS */}
        <div className="space-y-4 pt-4 border-t border-slate-800">
          <h3 className="text-xs font-bold text-slate-200 uppercase font-mono tracking-wider flex items-center gap-2">
            <Folder className="w-4 h-4 text-emerald-400" />
            2. Target Filesystem Roots & Directory Paths ({config.targetPaths.length} Active Target Paths)
          </h3>

          <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
            <div className="flex flex-wrap gap-2">
              {config.targetPaths.map((tp, idx) => (
                <div
                  key={idx}
                  className="bg-slate-900 border border-slate-700 text-slate-200 font-mono text-xs px-3 py-1.5 rounded-lg flex items-center gap-2"
                >
                  <Folder className="w-3.5 h-3.5 text-amber-400" />
                  <span>{tp}</span>
                  <button
                    type="button"
                    onClick={() => handleRemoveTargetPath(idx)}
                    className="text-slate-500 hover:text-rose-400 transition-colors ml-1"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>

            <div className="flex gap-2 pt-2">
              <input
                type="text"
                placeholder="Enter relative or absolute path (e.g. /var/data/logs or ./storage_bucket)"
                value={newTargetPath}
                onChange={e => setNewTargetPath(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') handleAddTargetPath(newTargetPath); }}
                className="flex-1 bg-slate-900 border border-slate-700 text-slate-100 rounded-lg p-2 text-xs font-mono outline-none focus:border-indigo-500"
              />
              <button
                type="button"
                onClick={() => handleAddTargetPath(newTargetPath)}
                className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3 py-2 rounded-lg text-xs font-bold font-mono flex items-center gap-1 transition-all"
              >
                <Plus className="w-3.5 h-3.5" /> Add Path
              </button>
            </div>

            <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-400 pt-1">
              <span className="font-semibold text-slate-300">Quick Target Presets:</span>
              {[
                './storage_bucket',
                'backend/uploads',
                './storage_bucket/quarantine_staging',
                '/var/data/compliance'
              ].map((p, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => handleAddTargetPath(p)}
                  className="px-2 py-0.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded font-mono text-[10px] text-indigo-300"
                >
                  + {p}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* SECTION 3: SCAN FOCUS & DETECTION MODULES */}
        <div className="space-y-4 pt-4 border-t border-slate-800">
          <h3 className="text-xs font-bold text-slate-200 uppercase font-mono tracking-wider flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            3. Scheduled Scan Scope & Detection Focus Modules
          </h3>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {[
              { id: 'SECURITY', name: 'Security & Audit Rules', desc: 'SOC2, ISO27001, HIPAA, GDPR rulesets' },
              { id: 'SECRETS', name: 'Secrets & API Keys', desc: 'AWS, Stripe, Private keys, JWT signatures' },
              { id: 'PII', name: 'PII & Financial Data', desc: 'SSNs, Credit Cards, Medical context' },
              { id: 'DOCUMENT', name: 'Unencrypted Documents', desc: 'Confidential PDFs, Office Docs, Archives' }
            ].map(mod => {
              const active = config.scanTypes.includes(mod.id as any);
              return (
                <button
                  key={mod.id}
                  type="button"
                  onClick={() => handleToggleScanType(mod.id as any)}
                  className={`p-3.5 rounded-xl border text-left transition-all ${
                    active
                      ? 'bg-slate-800/80 border-emerald-500 text-white'
                      : 'bg-slate-950 border-slate-800 text-slate-500 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-bold font-mono text-slate-200">{mod.name}</span>
                    <div className={`w-4 h-4 rounded flex items-center justify-center text-[10px] font-bold ${
                      active ? 'bg-emerald-500 text-slate-950' : 'border border-slate-700 text-transparent'
                    }`}>
                      ✓
                    </div>
                  </div>
                  <p className="text-[11px] text-slate-400">{mod.desc}</p>
                </button>
              );
            })}
          </div>
        </div>

        {/* SECTION 4: AUTOMATED REMEDIATION & ALERTS */}
        <div className="space-y-4 pt-4 border-t border-slate-800">
          <h3 className="text-xs font-bold text-slate-200 uppercase font-mono tracking-wider flex items-center gap-2">
            <Mail className="w-4 h-4 text-emerald-400" />
            4. Automated Remediations & Post-Scan Notifications
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-bold text-slate-200 block">Auto-Quarantine Critical Findings</span>
                  <span className="text-[11px] text-slate-400">Move critical risk items immediately to local quarantine staging.</span>
                </div>
                <input
                  type="checkbox"
                  checked={config.autoQuarantineCritical ?? false}
                  onChange={e => updateConfig({ autoQuarantineCritical: e.target.checked })}
                  className="w-4 h-4 accent-emerald-500 rounded cursor-pointer"
                />
              </div>
              <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
                <div>
                  <span className="text-xs font-bold text-slate-200 block">Generate Executive PDF Report</span>
                  <span className="text-[11px] text-slate-400">Automatically assemble printable compliance summary upon completion.</span>
                </div>
                <input
                  type="checkbox"
                  checked={config.generateReportOnComplete ?? true}
                  onChange={e => updateConfig({ generateReportOnComplete: e.target.checked })}
                  className="w-4 h-4 accent-emerald-500 rounded cursor-pointer"
                />
              </div>
            </div>

            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-200 block">Email & Webhook Scan Summary Alert</span>
                <input
                  type="checkbox"
                  checked={config.notifyOnCompletion ?? true}
                  onChange={e => updateConfig({ notifyOnCompletion: e.target.checked })}
                  className="w-4 h-4 accent-emerald-500 rounded cursor-pointer"
                />
              </div>
              <div>
                <label className="block text-[11px] text-slate-400 mb-1 font-mono">Notification Recipient Email</label>
                <input
                  type="email"
                  value={config.notificationEmail || ''}
                  onChange={e => updateConfig({ notificationEmail: e.target.value })}
                  placeholder="security-alerts@organization.com"
                  className="w-full bg-slate-900 border border-slate-700 text-slate-100 rounded-lg p-2 text-xs font-mono outline-none focus:border-indigo-500"
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* SECTION 5: SCHEDULED SCAN EXECUTION HISTORY LOG */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-indigo-400" />
              Scheduled Scan Execution History Logs ({history.length} Runs Logged)
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Audit log of automated background scans executed by the engine ticker or manual test triggers.
            </p>
          </div>
          <button
            onClick={fetchHistory}
            disabled={loadingHistory}
            className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3 py-1.5 rounded-lg text-xs font-mono flex items-center gap-1.5 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loadingHistory ? 'animate-spin' : ''}`} /> Refresh Logs
          </button>
        </div>

        {history.length === 0 ? (
          <div className="p-8 text-center bg-slate-950 rounded-xl border border-slate-800 text-xs text-slate-500 font-mono">
            No scheduled scan runs logged yet. Click "Run Scheduled Scan Now" above to launch a manual test run.
          </div>
        ) : (
          <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-950">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/80 border-b border-slate-800 text-slate-400 font-bold uppercase text-[10px]">
                <tr>
                  <th className="p-3">Run ID</th>
                  <th className="p-3">Trigger Type</th>
                  <th className="p-3">Started At</th>
                  <th className="p-3">Duration</th>
                  <th className="p-3">Files</th>
                  <th className="p-3">Critical / High</th>
                  <th className="p-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {history.map((h, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/40">
                    <td className="p-3 text-indigo-400 font-bold">{h.id}</td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 bg-slate-900 border border-slate-800 rounded text-[10px]">
                        {h.trigger_type}
                      </span>
                    </td>
                    <td className="p-3 text-slate-400">
                      {new Date(h.started_at).toLocaleString()}
                    </td>
                    <td className="p-3 text-slate-400">{h.duration_ms} ms</td>
                    <td className="p-3 font-bold text-white">{h.total_files}</td>
                    <td className="p-3">
                      <span className="text-amber-400 font-bold">{h.critical_count}</span> / <span className="text-yellow-400">{h.high_count}</span>
                    </td>
                    <td className="p-3">
                      {h.status === 'SUCCESS' ? (
                        <span className="px-2 py-0.5 bg-emerald-950 text-emerald-400 font-bold text-[10px] rounded border border-emerald-800">
                          ✓ SUCCESS
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 bg-amber-950 text-amber-400 font-bold text-[10px] rounded border border-amber-800">
                          ⚠️ WARNING
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
