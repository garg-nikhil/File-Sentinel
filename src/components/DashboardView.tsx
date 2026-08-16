import React from 'react';
import { DashboardStats, FileItem } from '../types';
import { SeverityBadge, ClassificationBadge } from './Badges';
import { Shield, FileCheck, ShieldAlert, FolderSearch, ArrowUpRight, Radio } from 'lucide-react';

interface DashboardProps {
  stats: DashboardStats | null;
  onNavigate: (tab: any) => void;
  onSelectFile: (fileId: string) => void;
  onStartQuickScan: () => void;
}

export const DashboardView: React.FC<DashboardProps> = ({
  stats,
  onNavigate,
  onSelectFile,
  onStartQuickScan
}) => {
  if (!stats) {
    return (
      <div className="p-8 text-center text-slate-400 animate-pulse">
        Loading FileSentinel telemetry dashboard...
      </div>
    );
  }

  const { totalScans, totalFilesScanned, riskBreakdown, quarantinedCount, highestRiskFiles, recentFindings } = stats;

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-6 rounded-xl shadow-sm">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Shield className="w-5 h-5 text-emerald-400" />
            Security Overview & Compliance posture
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Local-first inspection engine active. Static file parser ready for XLSX, CSV, DOCX, TXT, PPTX & PDF.
          </p>
        </div>
        <button
          id="btn-quick-scan"
          onClick={onStartQuickScan}
          className="inline-flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium px-4 py-2.5 rounded-lg transition-colors shadow-lg shadow-emerald-950/30"
        >
          <FolderSearch className="w-4 h-4" />
          Start New Scan
        </button>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
          <div className="text-xs text-slate-400 font-medium">Scanned Files</div>
          <div className="text-2xl font-bold text-slate-100 mt-1">{totalFilesScanned}</div>
          <div className="text-[11px] text-slate-500 mt-1">{totalScans} scan sessions</div>
        </div>

        <div className="bg-slate-900/80 border border-red-500/20 p-4 rounded-xl">
          <div className="text-xs text-red-400 font-medium flex items-center justify-between">
            Critical Risk
            <span className="w-2 h-2 rounded-full bg-red-500"></span>
          </div>
          <div className="text-2xl font-bold text-red-400 mt-1">{riskBreakdown.critical}</div>
          <div className="text-[11px] text-slate-500 mt-1">Score 80-100</div>
        </div>

        <div className="bg-slate-900/80 border border-orange-500/20 p-4 rounded-xl">
          <div className="text-xs text-orange-400 font-medium">High Risk</div>
          <div className="text-2xl font-bold text-orange-400 mt-1">{riskBreakdown.high}</div>
          <div className="text-[11px] text-slate-500 mt-1">Score 50-79</div>
        </div>

        <div className="bg-slate-900/80 border border-amber-500/20 p-4 rounded-xl">
          <div className="text-xs text-amber-300 font-medium">Medium Risk</div>
          <div className="text-2xl font-bold text-amber-300 mt-1">{riskBreakdown.medium}</div>
          <div className="text-[11px] text-slate-500 mt-1">Score 20-49</div>
        </div>

        <div className="bg-slate-900/80 border border-emerald-500/20 p-4 rounded-xl">
          <div className="text-xs text-emerald-400 font-medium">Safe / Low</div>
          <div className="text-2xl font-bold text-emerald-400 mt-1">{riskBreakdown.safe + riskBreakdown.low}</div>
          <div className="text-[11px] text-slate-500 mt-1">Score 0-19</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
          <div className="text-xs text-slate-400 font-medium flex items-center justify-between">
            Quarantine
            <ShieldAlert className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-purple-400 mt-1">{quarantinedCount}</div>
          <div className="text-[11px] text-slate-500 mt-1">Vaulted files</div>
        </div>
      </div>

      {/* Grid: Highest Risk Files & Recent Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Highest Risk Files */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              Highest-Risk Scanned Files
            </h3>
            <button
              onClick={() => onNavigate('files')}
              className="text-xs text-emerald-400 hover:text-emerald-300 font-medium flex items-center gap-1"
            >
              View All <ArrowUpRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-3">
            {highestRiskFiles.length === 0 ? (
              <p className="text-sm text-slate-500 italic py-4 text-center">No high risk files scanned yet.</p>
            ) : (
              highestRiskFiles.map(f => (
                <div
                  key={f.file_id}
                  onClick={() => onSelectFile(f.file_id)}
                  className="p-3.5 bg-slate-950/60 border border-slate-800/80 rounded-lg hover:border-slate-700 cursor-pointer transition-colors flex items-center justify-between"
                >
                  <div className="min-w-0 pr-3">
                    <div className="text-sm font-mono font-medium text-slate-200 truncate">{f.filename}</div>
                    <div className="text-xs text-slate-500 truncate mt-0.5">{f.path}</div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <ClassificationBadge classification={f.classification} />
                    <div className="text-right">
                      <div className="text-sm font-bold text-red-400 font-mono">{f.risk_score} / 100</div>
                      <div className="text-[10px] text-slate-500 uppercase">Risk Score</div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Recent Findings */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <Radio className="w-4 h-4 text-amber-400" />
              Recent DLP Findings
            </h3>
            <button
              onClick={() => onNavigate('findings')}
              className="text-xs text-emerald-400 hover:text-emerald-300 font-medium flex items-center gap-1"
            >
              View Findings Log <ArrowUpRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-3">
            {recentFindings.length === 0 ? (
              <p className="text-sm text-slate-500 italic py-4 text-center">No rule findings detected yet.</p>
            ) : (
              recentFindings.map(f => (
                <div key={f.finding_id} className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-lg space-y-1.5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={f.severity} />
                      <span className="text-xs font-semibold text-slate-300">{f.title}</span>
                    </div>
                    <span className="text-[11px] font-mono text-slate-500">{(f as any).filename}</span>
                  </div>
                  <p className="text-xs text-slate-400 line-clamp-1">{f.description}</p>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
