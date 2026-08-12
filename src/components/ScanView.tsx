import React, { useState, useEffect } from 'react';
import { ScanSession } from '../types';
import { api } from '../services/api';
import { FolderSearch, Play, CheckCircle2, AlertTriangle, ShieldCheck, FileCode } from 'lucide-react';

interface ScanViewProps {
  onScanComplete: (scanId: string) => void;
  activeScan: ScanSession | null;
  setActiveScan: (scan: ScanSession | null) => void;
}

export const ScanView: React.FC<ScanViewProps> = ({
  onScanComplete,
  activeScan,
  setActiveScan
}) => {
  const [folderPath, setFolderPath] = useState('./sample-files');
  const [isScanning, setIsScanning] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const presets = [
    { label: 'All Sample Datasets', path: './sample-files' },
    { label: 'Finance & Payroll', path: './sample-files/finance' },
    { label: 'Developer Credentials', path: './sample-files/dev-keys' },
    { label: 'HR Directory', path: './sample-files/hr' },
    { label: 'Network & Security Map', path: './sample-files/security' },
    { label: 'Public Documents (Safe)', path: './sample-files/public' }
  ];

  useEffect(() => {
    let timer: any;
    if (activeScan && activeScan.status === 'SCANNING') {
      setIsScanning(true);
      timer = setInterval(async () => {
        try {
          const updated = await api.getScanProgress(activeScan.scan_id);
          setActiveScan(updated);
          if (updated.status === 'COMPLETED' || updated.status === 'FAILED') {
            setIsScanning(false);
            clearInterval(timer);
            onScanComplete(updated.scan_id);
          }
        } catch (e) {
          console.error(e);
        }
      }, 500);
    }
    return () => clearInterval(timer);
  }, [activeScan?.scan_id, activeScan?.status]);

  const handleStartScan = async () => {
    try {
      setErrorMsg(null);
      setIsScanning(true);
      const session = await api.startScan(folderPath);
      setActiveScan(session);
    } catch (err: any) {
      setIsScanning(false);
      setErrorMsg(err.message || 'Failed to initialize scan engine');
    }
  };

  const progressPercent = activeScan && activeScan.total_files > 0
    ? Math.round((activeScan.processed_files / activeScan.total_files) * 100)
    : 0;

  return (
    <div className="p-8 max-w-5xl mx-auto space-y-8">
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <FolderSearch className="w-5 h-5 text-emerald-400" />
          Target Folder Selection & Scan Execution
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Select a local root directory for recursive file discovery and static compliance analysis.
        </p>
      </div>

      {/* Target Directory Selection Box */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
            Target Directory Path
          </label>
          <div className="flex gap-3">
            <input
              type="text"
              value={folderPath}
              onChange={e => setFolderPath(e.target.value)}
              placeholder="e.g. ./sample-files or C:\Users\Documents"
              disabled={isScanning}
              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-sm font-mono text-slate-100 focus:outline-none focus:border-emerald-500 disabled:opacity-50"
            />
            <button
              id="btn-execute-scan"
              onClick={handleStartScan}
              disabled={isScanning || !folderPath.trim()}
              className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-6 py-2.5 rounded-lg flex items-center gap-2 text-sm transition-colors disabled:opacity-50 shadow-md"
            >
              <Play className="w-4 h-4 fill-current" />
              {isScanning ? 'Scanning...' : 'Start Scan'}
            </button>
          </div>
          {errorMsg && <p className="text-xs text-red-400 mt-2">{errorMsg}</p>}
        </div>

        {/* Quick Select Presets */}
        <div>
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block mb-2.5">
            Quick Select Preset Target Folders
          </span>
          <div className="flex flex-wrap gap-2">
            {presets.map(p => (
              <button
                key={p.path}
                onClick={() => setFolderPath(p.path)}
                disabled={isScanning}
                className={`text-xs px-3 py-1.5 rounded-md font-mono transition-colors border ${
                  folderPath === p.path
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/40 font-semibold'
                    : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        {/* Supported Ext List */}
        <div className="border-t border-slate-800/80 pt-4 flex flex-wrap items-center justify-between gap-4 text-xs text-slate-400">
          <span className="font-semibold text-slate-300">Supported Formats:</span>
          <div className="flex gap-2">
            {['.XLSX', '.CSV', '.DOCX', '.TXT', '.PPTX', '.PDF'].map(ext => (
              <span key={ext} className="bg-slate-950 border border-slate-800 text-slate-300 px-2 py-1 rounded font-mono font-medium">
                {ext}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Real-time Scan Progress Section */}
      {activeScan && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                {activeScan.status === 'SCANNING' ? (
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-400 animate-ping"></span>
                ) : (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                )}
                Scan Session: <span className="font-mono text-emerald-400">{activeScan.scan_id}</span>
              </h3>
              <p className="text-xs text-slate-400 mt-1 font-mono">{activeScan.root_path}</p>
            </div>
            <span className={`px-3 py-1 rounded-full text-xs font-mono font-bold border ${
              activeScan.status === 'SCANNING' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
            }`}>
              {activeScan.status}
            </span>
          </div>

          {/* Progress bar */}
          <div className="space-y-2">
            <div className="flex justify-between text-xs font-mono">
              <span className="text-slate-400">
                Processed {activeScan.processed_files} of {activeScan.total_files} files
              </span>
              <span className="text-emerald-400 font-bold">{progressPercent}%</span>
            </div>
            <div className="w-full h-3 bg-slate-950 rounded-full overflow-hidden border border-slate-800 p-0.5">
              <div
                className="h-full bg-gradient-to-r from-emerald-600 to-emerald-400 rounded-full transition-all duration-300"
                style={{ width: `${progressPercent}%` }}
              ></div>
            </div>
            {activeScan.current_file && (
              <div className="text-xs text-slate-400 font-mono truncate">
                Current file: <span className="text-slate-200">{activeScan.current_file}</span>
              </div>
            )}
          </div>

          {/* Live telemetry counters */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3 pt-2 text-center">
            <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
              <div className="text-[10px] text-red-400 uppercase font-semibold">Critical</div>
              <div className="text-lg font-bold text-red-400 font-mono">{activeScan.critical_count}</div>
            </div>
            <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
              <div className="text-[10px] text-orange-400 uppercase font-semibold">High</div>
              <div className="text-lg font-bold text-orange-400 font-mono">{activeScan.high_count}</div>
            </div>
            <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
              <div className="text-[10px] text-amber-300 uppercase font-semibold">Medium</div>
              <div className="text-lg font-bold text-amber-300 font-mono">{activeScan.medium_count}</div>
            </div>
            <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
              <div className="text-[10px] text-emerald-400 uppercase font-semibold">Safe</div>
              <div className="text-lg font-bold text-emerald-400 font-mono">{activeScan.safe_count}</div>
            </div>
            <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
              <div className="text-[10px] text-slate-400 uppercase font-semibold">Errors</div>
              <div className="text-lg font-bold text-slate-400 font-mono">{activeScan.error_count}</div>
            </div>
          </div>
        </div>
      )}

      {/* Safety Principles Panel */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 text-xs text-slate-400 space-y-3">
        <h4 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          Deterministic Security & Non-Execution Mandate
        </h4>
        <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 list-disc list-inside">
          <li>Never executes files, scripts, or macros.</li>
          <li>SHA-256 fingerprinting guarantees file content identity.</li>
          <li>Static parsing prevents zip-bomb & memory overheads.</li>
          <li>DLP rules run locally without remote cloud dependencies.</li>
        </ul>
      </div>
    </div>
  );
};
