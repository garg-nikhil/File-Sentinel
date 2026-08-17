import React, { useState, useEffect } from 'react';
import {
  Laptop,
  Usb,
  Globe,
  Mail,
  MessageSquare,
  Cloud,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  HelpCircle,
  Play,
  RotateCcw,
  Shield,
  FileText,
  Copy,
  Check,
  HardDrive,
  Info,
  Clock,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { api } from '../services/api';
import {
  EndpointAssessment,
  USBDetectionResult,
  WebTargetResult,
  DetectionCategory
} from '../types';

export const EndpointComplianceView: React.FC = () => {
  const [assessment, setAssessment] = useState<EndpointAssessment | null>(null);
  const [history, setHistory] = useState<EndpointAssessment[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [assessing, setAssessing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedEvidence, setCopiedEvidence] = useState<boolean>(false);
  const [showEvidence, setShowEvidence] = useState<boolean>(false);
  const [activeWebTab, setActiveWebTab] = useState<DetectionCategory>('SOCIAL_MEDIA');

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [latest, list] = await Promise.all([
        api.getLatestEndpointAssessment().catch(() => null),
        api.getEndpointAssessments(15).catch(() => [])
      ]);
      setAssessment(latest);
      setHistory(list);
    } catch (err: any) {
      setError(err?.message || 'Failed to load endpoint compliance status');
    } finally {
      setLoading(false);
    }
  };

  const handleRunAssessment = async () => {
    setAssessing(true);
    setError(null);
    try {
      const result = await api.runEndpointAssessment();
      setAssessment(result);
      // Refresh history list
      const updatedHistory = await api.getEndpointAssessments(15).catch(() => []);
      setHistory(updatedHistory);
    } catch (err: any) {
      setError(err?.message || 'Failed to execute endpoint compliance assessment');
    } finally {
      setAssessing(false);
    }
  };

  const handleCopyEvidence = () => {
    if (!assessment?.evidence_text) return;
    navigator.clipboard.writeText(assessment.evidence_text);
    setCopiedEvidence(true);
    setTimeout(() => setCopiedEvidence(false), 2000);
  };

  const getOverallStatusBadge = (status?: string) => {
    switch (status) {
      case 'COMPLIANT':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3.5 h-3.5" /> COMPLIANT
          </span>
        );
      case 'NON_COMPLIANT':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <XCircle className="w-3.5 h-3.5" /> NON-COMPLIANT
          </span>
        );
      case 'ATTENTION_REQUIRED':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3.5 h-3.5" /> ATTENTION REQUIRED
          </span>
        );
      case 'INDETERMINATE':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/30">
            <HelpCircle className="w-3.5 h-3.5" /> INDETERMINATE
          </span>
        );
    }
  };

  const getWebStatusBadge = (status: string) => {
    switch (status) {
      case 'BLOCKED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <CheckCircle2 className="w-3 h-3" /> BLOCKED
          </span>
        );
      case 'ACCESSIBLE':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <XCircle className="w-3 h-3" /> ACCESSIBLE
          </span>
        );
      case 'INDETERMINATE':
      case 'UNREACHABLE':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertTriangle className="w-3 h-3" /> {status}
          </span>
        );
    }
  };

  return (
    <div id="endpoint-compliance-view" className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 text-[10px] font-bold tracking-wider uppercase rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              Phase A Detection Engine
            </span>
            <span className="px-2 py-0.5 text-[10px] font-bold tracking-wider uppercase rounded bg-slate-800 text-slate-300 border border-slate-700">
              Read-Only Telemetry
            </span>
          </div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2.5">
            <Laptop className="w-5 h-5 text-cyan-400" />
            Endpoint Compliance Posture
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time, bounded detection of USB mass storage policies, attached peripherals, and corporate web communication filtering.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {assessment && getOverallStatusBadge(assessment.overall_status)}

          <button
            id="btn-run-assessment"
            onClick={handleRunAssessment}
            disabled={assessing}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs shadow-md transition disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {assessing ? (
              <>
                <RotateCcw className="w-3.5 h-3.5 animate-spin" />
                Probing Endpoint...
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                Run Assessment
              </>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="p-12 text-center text-slate-400 text-sm flex flex-col items-center justify-center gap-3">
          <RotateCcw className="w-6 h-6 animate-spin text-cyan-400" />
          <span>Loading endpoint telemetry data...</span>
        </div>
      ) : !assessment ? (
        <div className="p-12 text-center bg-slate-900 border border-slate-800 rounded-xl">
          <Laptop className="w-10 h-10 text-slate-500 mx-auto mb-3" />
          <h3 className="text-sm font-semibold text-slate-200">No Assessment Recorded Yet</h3>
          <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
            Click &quot;Run Assessment&quot; above to perform live bounded detection of USB storage and web communication access controls on this endpoint.
          </p>
          <button
            onClick={handleRunAssessment}
            disabled={assessing}
            className="mt-4 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium cursor-pointer"
          >
            Start Initial Assessment
          </button>
        </div>
      ) : (
        <>
          {/* Metadata Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-900/60 border border-slate-800 rounded-xl p-3.5 text-xs">
            <div>
              <span className="text-slate-500 block text-[11px]">Device Identifier</span>
              <span className="font-mono text-slate-200 font-semibold">{assessment.device_id}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[11px]">Target Platform</span>
              <span className="text-slate-200 capitalize">{assessment.platform}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[11px]">Assessment Time</span>
              <span className="text-slate-200">{new Date(assessment.timestamp).toLocaleString()}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[11px]">Detection Engine</span>
              <span className="text-slate-200">{assessment.application_version}</span>
            </div>
          </div>

          {/* Top Category Summary Grid */}
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            {/* USB Mass Storage Card */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <Usb className="w-4 h-4 text-cyan-400" /> USB Storage
                </span>
                <span
                  className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                    assessment.usb_result.status === 'DISABLED'
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                      : assessment.usb_result.status === 'ENABLED'
                      ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                      : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                  }`}
                >
                  {assessment.usb_result.status}
                </span>
              </div>
              <div className="mt-3">
                <div className="text-2xl font-bold text-slate-100">
                  {assessment.usb_result.connectedDeviceCount}
                </div>
                <span className="text-[11px] text-slate-400">
                  Storage devices attached
                </span>
              </div>
              <div className="mt-2 text-[10px] text-slate-500">
                Method: {assessment.usb_result.detectionMethod}
              </div>
            </div>

            {/* Social Media Card */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <Globe className="w-4 h-4 text-indigo-400" /> Social Media
                </span>
                <span className="text-[10px] text-slate-400 font-mono">
                  {assessment.category_summaries.SOCIAL_MEDIA?.blocked || 0}/{assessment.category_summaries.SOCIAL_MEDIA?.total || 0} Blocked
                </span>
              </div>
              <div className="mt-3">
                <div className="text-2xl font-bold text-slate-100">
                  {assessment.category_summaries.SOCIAL_MEDIA?.accessible || 0}
                </div>
                <span className="text-[11px] text-slate-400">
                  Accessible sites detected
                </span>
              </div>
              <div className="mt-2 text-[10px] text-slate-500">
                Total targets: {assessment.category_summaries.SOCIAL_MEDIA?.total || 0}
              </div>
            </div>

            {/* Personal Email Card */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <Mail className="w-4 h-4 text-emerald-400" /> Personal Email
                </span>
                <span className="text-[10px] text-slate-400 font-mono">
                  {assessment.category_summaries.PERSONAL_EMAIL?.blocked || 0}/{assessment.category_summaries.PERSONAL_EMAIL?.total || 0} Blocked
                </span>
              </div>
              <div className="mt-3">
                <div className="text-2xl font-bold text-slate-100">
                  {assessment.category_summaries.PERSONAL_EMAIL?.accessible || 0}
                </div>
                <span className="text-[11px] text-slate-400">
                  Accessible email portals
                </span>
              </div>
              <div className="mt-2 text-[10px] text-slate-500">
                Total targets: {assessment.category_summaries.PERSONAL_EMAIL?.total || 0}
              </div>
            </div>

            {/* Messaging Apps Card */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <MessageSquare className="w-4 h-4 text-amber-400" /> Messaging
                </span>
                <span className="text-[10px] text-slate-400 font-mono">
                  {assessment.category_summaries.MESSAGING?.blocked || 0}/{assessment.category_summaries.MESSAGING?.total || 0} Blocked
                </span>
              </div>
              <div className="mt-3">
                <div className="text-2xl font-bold text-slate-100">
                  {assessment.category_summaries.MESSAGING?.accessible || 0}
                </div>
                <span className="text-[11px] text-slate-400">
                  Accessible web chat apps
                </span>
              </div>
              <div className="mt-2 text-[10px] text-slate-500">
                Total targets: {assessment.category_summaries.MESSAGING?.total || 0}
              </div>
            </div>

            {/* Cloud Storage Card */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <Cloud className="w-4 h-4 text-sky-400" /> Cloud Storage
                </span>
                <span className="text-[10px] text-slate-400 font-mono">
                  {assessment.category_summaries.CLOUD_STORAGE?.blocked || 0}/{assessment.category_summaries.CLOUD_STORAGE?.total || 0} Blocked
                </span>
              </div>
              <div className="mt-3">
                <div className="text-2xl font-bold text-slate-100">
                  {assessment.category_summaries.CLOUD_STORAGE?.accessible || 0}
                </div>
                <span className="text-[11px] text-slate-400">
                  Accessible cloud drives
                </span>
              </div>
              <div className="mt-2 text-[10px] text-slate-500">
                Total targets: {assessment.category_summaries.CLOUD_STORAGE?.total || 0}
              </div>
            </div>
          </div>

          {/* USB Storage Detailed Section */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <HardDrive className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-slate-200">
                  USB Mass Storage Device Inventory & Registry Policy
                </h3>
              </div>
              <div className="text-[11px] text-slate-400 flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5 text-slate-500" />
                Keyboards, mice & HID peripherals are excluded from storage policy checks.
              </div>
            </div>

            {assessment.usb_result.connectedStorageDevices && assessment.usb_result.connectedStorageDevices.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="text-slate-400 bg-slate-950/60 uppercase font-mono text-[10px]">
                    <tr>
                      <th className="p-2.5 rounded-l">Device Type</th>
                      <th className="p-2.5">Manufacturer</th>
                      <th className="p-2.5">Model</th>
                      <th className="p-2.5">Device Identifier</th>
                      <th className="p-2.5 rounded-r">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 text-slate-300">
                    {assessment.usb_result.connectedStorageDevices.map((dev, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/40">
                        <td className="p-2.5 font-medium text-slate-200 flex items-center gap-2">
                          <Usb className="w-3.5 h-3.5 text-cyan-400" />
                          {dev.device_type}
                        </td>
                        <td className="p-2.5">{dev.manufacturer}</td>
                        <td className="p-2.5 font-mono">{dev.model}</td>
                        <td className="p-2.5 font-mono text-slate-400">{dev.device_id || 'N/A'}</td>
                        <td className="p-2.5">
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            {dev.connection_status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-4 rounded-lg bg-slate-950/40 border border-slate-800/80 text-xs text-slate-400 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                <span>No removable USB Mass Storage drives attached to this endpoint.</span>
              </div>
            )}
          </div>

          {/* Web Access Filtering Matrix */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3 mb-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <Globe className="w-4 h-4 text-indigo-400" />
                  Web Communication & Access Filtering Targets
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Probes measure live corporate proxy, DNS sinkhole, and gateway policy enforcement.
                </p>
              </div>

              {/* Category Filter Tabs */}
              <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-lg border border-slate-800">
                {(['SOCIAL_MEDIA', 'PERSONAL_EMAIL', 'MESSAGING', 'CLOUD_STORAGE'] as DetectionCategory[]).map(cat => (
                  <button
                    key={cat}
                    onClick={() => setActiveWebTab(cat)}
                    className={`px-2.5 py-1 text-xs rounded font-medium transition cursor-pointer ${
                      activeWebTab === cat
                        ? 'bg-slate-800 text-slate-100 shadow'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {cat === 'SOCIAL_MEDIA'
                      ? 'Social'
                      : cat === 'PERSONAL_EMAIL'
                      ? 'Email'
                      : cat === 'MESSAGING'
                      ? 'Chat'
                      : 'Cloud'}
                  </button>
                ))}
              </div>
            </div>

            {/* Results Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="text-slate-400 bg-slate-950/60 uppercase font-mono text-[10px]">
                  <tr>
                    <th className="p-2.5 rounded-l">Service Name</th>
                    <th className="p-2.5">Domain</th>
                    <th className="p-2.5">Status</th>
                    <th className="p-2.5">Confidence</th>
                    <th className="p-2.5">Detection Method</th>
                    <th className="p-2.5 rounded-r">Response Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 text-slate-300">
                  {assessment.web_results
                    .filter(r => r.category === activeWebTab)
                    .map((item, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/40">
                        <td className="p-2.5 font-medium text-slate-200">{item.service}</td>
                        <td className="p-2.5 font-mono text-slate-400">{item.target_domain}</td>
                        <td className="p-2.5">{getWebStatusBadge(item.status)}</td>
                        <td className="p-2.5">
                          <span className="text-[11px] text-slate-400 font-mono">{item.confidence}</span>
                        </td>
                        <td className="p-2.5 text-[11px] text-slate-400">{item.detectionMethod}</td>
                        <td className="p-2.5 text-[11px] text-slate-400">
                          {item.reason || (item.httpStatusCode ? `HTTP ${item.httpStatusCode}` : 'OK')}
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Deterministic Live Telemetry Evidence Box */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-emerald-400" />
                <h3 className="text-sm font-semibold text-slate-200">
                  Deterministic Audit & Compliance Telemetry Export
                </h3>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopyEvidence}
                  className="flex items-center gap-1 px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium cursor-pointer"
                >
                  {copiedEvidence ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedEvidence ? 'Copied' : 'Copy Evidence'}
                </button>
                <button
                  onClick={() => setShowEvidence(!showEvidence)}
                  className="p-1 text-slate-400 hover:text-slate-200 cursor-pointer"
                >
                  {showEvidence ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {showEvidence && (
              <div className="mt-4">
                <pre className="p-4 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono text-emerald-400 overflow-x-auto whitespace-pre-wrap max-h-72 leading-relaxed">
                  {assessment.evidence_text}
                </pre>
              </div>
            )}
          </div>

          {/* Historical Assessments Log */}
          {history.length > 1 && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2 mb-3">
                <Clock className="w-4 h-4 text-slate-400" />
                Recent Endpoint Assessment History
              </h3>
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="text-slate-400 bg-slate-950/60 uppercase font-mono text-[10px]">
                    <tr>
                      <th className="p-2.5 rounded-l">Assessment ID</th>
                      <th className="p-2.5">Timestamp</th>
                      <th className="p-2.5">Device ID</th>
                      <th className="p-2.5">Platform</th>
                      <th className="p-2.5">Status</th>
                      <th className="p-2.5 rounded-r text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 text-slate-300">
                    {history.map((h, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/40">
                        <td className="p-2.5 font-mono text-slate-300">{h.id}</td>
                        <td className="p-2.5 text-slate-400">{new Date(h.timestamp).toLocaleString()}</td>
                        <td className="p-2.5 font-mono text-slate-400">{h.device_id}</td>
                        <td className="p-2.5 capitalize">{h.platform}</td>
                        <td className="p-2.5">{getOverallStatusBadge(h.overall_status)}</td>
                        <td className="p-2.5 text-right">
                          <button
                            onClick={() => setAssessment(h)}
                            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 font-medium text-xs cursor-pointer"
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};
