import React, { useState, useEffect, useRef } from 'react';
import { ScanSession } from '../types';
import { api } from '../services/api';
import { FolderSearch, Play, CheckCircle2, AlertTriangle, ShieldCheck, FileCode, UploadCloud } from 'lucide-react';

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
  const [folderPath, setFolderPath] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  
  const fileInputRef = useRef<HTMLInputElement>(null);

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

  const handleStartScan = async (pathOverride?: string) => {
    try {
      setErrorMsg(null);
      setIsScanning(true);
      const target = pathOverride || folderPath;
      const session = await api.startScan(target);
      setActiveScan(session);
    } catch (err: any) {
      setIsScanning(false);
      setErrorMsg(err.message || 'Failed to initialize scan engine');
    }
  };

  const handleDirectorySelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || e.target.files.length === 0) return;
    
    try {
      setIsUploading(true);
      setErrorMsg(null);
      setUploadProgress(0);
      
      const files = Array.from(e.target.files) as File[];
      const uploadedPath = await api.uploadDirectory(files, (pct) => {
        setUploadProgress(pct);
      });
      
      setFolderPath(uploadedPath);
      setIsUploading(false);
      setUploadProgress(0);
      
      // Optionally start scan automatically
      // handleStartScan(uploadedPath);
    } catch (err: any) {
      setIsUploading(false);
      setUploadProgress(0);
      setErrorMsg(err.message || 'Failed to upload directory');
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
          Scans files, analyzes security risks, and evaluates audit compliance.
        </p>
      </div>

      {/* Target Directory Selection Box */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
        <div>
          <div className="flex justify-between items-center mb-2">
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
              Target Directory Path
            </label>
            <button 
              onClick={() => fileInputRef.current?.click()}
              disabled={isScanning || isUploading}
              className="text-xs text-emerald-400 hover:text-emerald-300 flex items-center gap-1 font-medium transition-colors"
            >
              <UploadCloud className="w-3.5 h-3.5" />
              Upload Local Folder
            </button>
            {/* hidden directory input */}
            <input 
              type="file" 
              ref={fileInputRef} 
              onChange={handleDirectorySelect}
              className="hidden" 
              // @ts-ignore
              webkitdirectory="" 
              directory="" 
              multiple 
            />
          </div>
          <div className="flex gap-3">
            <input
              type="text"
              value={folderPath}
              onChange={e => setFolderPath(e.target.value)}
              placeholder="e.g. /path/to/folder or click 'Upload Local Folder' above"
              disabled={isScanning || isUploading}
              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-sm font-mono text-slate-100 focus:outline-none focus:border-emerald-500 disabled:opacity-50"
            />
            <button
              id="btn-execute-scan"
              onClick={() => handleStartScan()}
              disabled={isScanning || isUploading || !folderPath.trim()}
              className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-6 py-2.5 rounded-lg flex items-center gap-2 text-sm transition-colors disabled:opacity-50 shadow-md whitespace-nowrap"
            >
              <Play className="w-4 h-4 fill-current" />
              {isScanning ? 'Scanning...' : 'Scan Now'}
            </button>
          </div>
          {isUploading && (
            <div className="mt-3">
              <div className="flex justify-between text-xs text-slate-400 mb-1">
                <span>Uploading local folder...</span>
                <span>{uploadProgress}%</span>
              </div>
              <div className="h-1 bg-slate-800 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-emerald-500 transition-all duration-300"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
            </div>
          )}
          {errorMsg && <p className="text-xs text-red-400 mt-2">{errorMsg}</p>}
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
          <div className="space-y-4">
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
            </div>

            {activeScan.status === 'SCANNING' && (
              <div className="flex flex-col gap-1.5 text-xs font-mono bg-slate-950/50 p-4 rounded-lg border border-slate-800/50">
                <div className={activeScan.current_file === 'Discovering files...' ? 'text-emerald-400 font-semibold' : 'text-slate-500'}>
                  {activeScan.current_file === 'Discovering files...' ? 'Step 1/5 — Discovering files...' : '✓ Step 1/5 — Discovering files'}
                </div>
                <div className={activeScan.current_file !== 'Discovering files...' && activeScan.current_file !== 'Evaluating compliance...' && activeScan.current_file !== 'Finalizing results...' ? 'text-emerald-400 font-semibold' : activeScan.current_file === 'Evaluating compliance...' || activeScan.current_file === 'Finalizing results...' ? 'text-slate-500' : 'text-slate-600 opacity-50'}>
                  {activeScan.current_file === 'Evaluating compliance...' || activeScan.current_file === 'Finalizing results...' ? '✓ Step 2/5 — Extracting evidence' : 'Step 2/5 — Extracting evidence'}
                </div>
                <div className={activeScan.current_file !== 'Discovering files...' && activeScan.current_file !== 'Evaluating compliance...' && activeScan.current_file !== 'Finalizing results...' ? 'text-emerald-400 font-semibold' : activeScan.current_file === 'Evaluating compliance...' || activeScan.current_file === 'Finalizing results...' ? 'text-slate-500' : 'text-slate-600 opacity-50'}>
                  {activeScan.current_file === 'Evaluating compliance...' || activeScan.current_file === 'Finalizing results...' ? '✓ Step 3/5 — Security analysis' : 'Step 3/5 — Security analysis'}
                </div>
                <div className={activeScan.current_file === 'Evaluating compliance...' ? 'text-emerald-400 font-semibold' : activeScan.current_file === 'Finalizing results...' ? 'text-slate-500' : 'text-slate-600 opacity-50'}>
                  {activeScan.current_file === 'Finalizing results...' ? '✓ Step 4/5 — Audit compliance' : 'Step 4/5 — Audit compliance'}
                </div>
                <div className={activeScan.current_file === 'Finalizing results...' ? 'text-emerald-400 font-semibold' : 'text-slate-600 opacity-50'}>
                  Step 5/5 — Finalizing results
                </div>
              </div>
            )}

            {activeScan.current_file && activeScan.current_file !== 'Discovering files...' && activeScan.current_file !== 'Evaluating compliance...' && activeScan.current_file !== 'Finalizing results...' && (
              <div className="text-xs text-slate-400 font-mono truncate">
                Processing file: <span className="text-slate-200">{activeScan.current_file}</span>
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
