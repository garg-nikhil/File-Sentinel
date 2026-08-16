import React, { useState, useEffect, useRef } from 'react';
import { ScanSession } from '../types';
import { api } from '../services/api';
import { FolderSearch, Play, CheckCircle2, AlertTriangle, ShieldCheck, UploadCloud, Folder, Trash2, CheckSquare, Square } from 'lucide-react';

interface ScanViewProps {
  onScanComplete: (scanId: string) => void;
  activeScan: ScanSession | null;
  setActiveScan: (scan: ScanSession | null) => void;
}

interface UploadedFolder {
  id: string;
  folderName: string;
  rootPath: string;
  fileCount: number;
  status: 'uploading' | 'completed' | 'error';
  progress: number;
  selected: boolean;
  errorMsg?: string;
}

export const ScanView: React.FC<ScanViewProps> = ({
  onScanComplete,
  activeScan,
  setActiveScan
}) => {
  const [uploadedFolders, setUploadedFolders] = useState<UploadedFolder[]>([]);
  const [isScanning, setIsScanning] = useState(false);
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

  const handleStartScan = async () => {
    const selectedFolders = uploadedFolders.filter(f => f.selected && f.status === 'completed');
    if (selectedFolders.length === 0) {
      setErrorMsg('Please upload and select at least one folder to scan.');
      return;
    }

    try {
      setErrorMsg(null);
      setIsScanning(true);
      const paths = selectedFolders.map(f => f.rootPath);
      const session = await api.startScan(paths);
      setActiveScan(session);
    } catch (err: any) {
      setIsScanning(false);
      setErrorMsg(err.message || 'Failed to initialize scan engine');
    }
  };

  const handleDirectorySelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || e.target.files.length === 0) return;
    
    const files = Array.from(e.target.files) as File[];
    const firstPath = (files[0] as any).webkitRelativePath || files[0]?.name || 'Uploaded Folder';
    const topFolder = firstPath.split('/')[0] || 'Uploaded Folder';
    
    const folderId = 'folder_' + Math.random().toString(36).substring(2, 9);
    
    const newFolderItem: UploadedFolder = {
      id: folderId,
      folderName: topFolder,
      rootPath: '',
      fileCount: files.length,
      status: 'uploading',
      progress: 0,
      selected: true
    };

    setUploadedFolders(prev => [...prev, newFolderItem]);
    setErrorMsg(null);

    // Reset file input value so same folder can be uploaded again if needed
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }

    try {
      const result = await api.uploadDirectory(files, (pct) => {
        setUploadedFolders(prev => prev.map(f => f.id === folderId ? { ...f, progress: pct } : f));
      });
      
      setUploadedFolders(prev => prev.map(f => f.id === folderId ? {
        ...f,
        rootPath: result.rootPath,
        fileCount: result.fileCount,
        status: 'completed',
        progress: 100,
        folderName: result.folderName || topFolder
      } : f));
    } catch (err: any) {
      setUploadedFolders(prev => prev.map(f => f.id === folderId ? {
        ...f,
        status: 'error',
        errorMsg: err.message || 'Upload failed'
      } : f));
    }
  };

  const toggleFolderSelection = (id: string) => {
    setUploadedFolders(prev => prev.map(f => f.id === id ? { ...f, selected: !f.selected } : f));
  };

  const removeFolder = (id: string) => {
    setUploadedFolders(prev => prev.filter(f => f.id !== id));
  };

  const toggleSelectAll = (select: boolean) => {
    setUploadedFolders(prev => prev.map(f => ({ ...f, selected: select })));
  };

  const progressPercent = activeScan && activeScan.total_files > 0
    ? Math.round((activeScan.processed_files / activeScan.total_files) * 100)
    : 0;

  const anyUploading = uploadedFolders.some(f => f.status === 'uploading');
  const selectedCompletedCount = uploadedFolders.filter(f => f.selected && f.status === 'completed').length;

  return (
    <div className="p-8 max-w-5xl mx-auto space-y-8">
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <FolderSearch className="w-5 h-5 text-emerald-400" />
          Target Folder Selection & Scan Execution
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Select multiple folders, upload local directories, and run compliance & security scans.
        </p>
      </div>

      {/* Target Directory Selection Box */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Uploaded Folders & Target Directories ({uploadedFolders.length})
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Select multiple folders to include in your compliance audit batch.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button 
              onClick={() => fileInputRef.current?.click()}
              disabled={isScanning}
              className="bg-slate-800 hover:bg-slate-700 text-emerald-400 border border-slate-700 text-xs px-4 py-2.5 rounded-lg flex items-center gap-2 font-medium transition-colors shadow-sm disabled:opacity-50"
            >
              <UploadCloud className="w-4 h-4" />
              Upload Local Folder
            </button>
            {/* hidden directory input supporting multiple selection */}
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
        </div>

        {/* Uploaded Folders List */}
        {uploadedFolders.length === 0 ? (
          <div className="border border-dashed border-slate-800 rounded-xl p-8 text-center bg-slate-950/40 space-y-3">
            <div className="w-12 h-12 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center mx-auto text-slate-500">
              <Folder className="w-6 h-6" />
            </div>
            <div>
              <p className="text-sm font-medium text-slate-300">No folders uploaded yet</p>
              <p className="text-xs text-slate-500 mt-1">Click 'Upload Local Folder' above to select one or more folders for analysis.</p>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="flex items-center justify-between px-2 text-xs text-slate-400 pb-1 border-b border-slate-800/80">
              <div className="flex items-center gap-2">
                <button 
                  onClick={() => toggleSelectAll(selectedCompletedCount < uploadedFolders.length)}
                  className="text-emerald-400 hover:text-emerald-300 font-medium flex items-center gap-1"
                >
                  {selectedCompletedCount === uploadedFolders.length ? <CheckSquare className="w-4 h-4" /> : <Square className="w-4 h-4" />}
                  {selectedCompletedCount === uploadedFolders.length ? 'Deselect All' : 'Select All'}
                </button>
              </div>
              <span>{selectedCompletedCount} of {uploadedFolders.length} folders selected for scan</span>
            </div>

            <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1">
              {uploadedFolders.map(folder => (
                <div 
                  key={folder.id}
                  className={`flex items-center justify-between p-4 rounded-xl border transition-all ${
                    folder.selected ? 'bg-slate-950 border-emerald-500/40 shadow-sm' : 'bg-slate-950/60 border-slate-800/80 opacity-75'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0 flex-1">
                    <button 
                      onClick={() => toggleFolderSelection(folder.id)}
                      disabled={folder.status !== 'completed'}
                      className="text-emerald-400 hover:text-emerald-300 focus:outline-none disabled:opacity-40"
                      title={folder.status === 'completed' ? 'Select/Deselect folder' : 'Uploading in progress'}
                    >
                      {folder.selected ? <CheckSquare className="w-5 h-5 text-emerald-400" /> : <Square className="w-5 h-5 text-slate-600" />}
                    </button>

                    <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 flex-shrink-0">
                      <Folder className="w-4 h-4" />
                    </div>

                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold text-slate-100 truncate">{folder.folderName}</span>
                        {folder.status === 'completed' && (
                          <span className="px-2 py-0.5 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10px] font-mono font-bold rounded-full">
                            Upload Finished
                          </span>
                        )}
                        {folder.status === 'uploading' && (
                          <span className="px-2 py-0.5 bg-amber-500/10 border border-amber-500/30 text-amber-400 text-[10px] font-mono font-bold rounded-full animate-pulse">
                            Uploading ({folder.progress}%)
                          </span>
                        )}
                        {folder.status === 'error' && (
                          <span className="px-2 py-0.5 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-[10px] font-mono font-bold rounded-full">
                            Upload Failed
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-3 text-xs text-slate-400 mt-0.5 font-mono">
                        <span className="truncate">{folder.rootPath || 'Preparing path...'}</span>
                        <span className="text-slate-300 font-semibold flex-shrink-0">• {folder.fileCount} files uploaded successfully</span>
                      </div>

                      {folder.status === 'uploading' && (
                        <div className="mt-2 h-1.5 bg-slate-900 rounded-full overflow-hidden max-w-md">
                          <div 
                            className="h-full bg-emerald-500 transition-all duration-300"
                            style={{ width: `${folder.progress}%` }}
                          />
                        </div>
                      )}
                      {folder.errorMsg && (
                        <p className="text-xs text-rose-400 mt-1 font-mono">{folder.errorMsg}</p>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 ml-4 flex-shrink-0">
                    <button
                      onClick={() => removeFolder(folder.id)}
                      disabled={isScanning}
                      className="p-2 text-slate-500 hover:text-rose-400 hover:bg-slate-900 rounded-lg transition-colors disabled:opacity-40"
                      title="Remove folder item"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ONE SINGLE SCAN NOW BUTTON */}
        <div className="pt-4 border-t border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="text-xs text-slate-400">
            {selectedCompletedCount > 0 ? (
              <span className="text-emerald-400 font-medium">Ready to scan {selectedCompletedCount} selected folder(s).</span>
            ) : (
              <span>Please select at least one uploaded folder above to scan.</span>
            )}
          </div>
          <button
            id="btn-execute-scan"
            onClick={handleStartScan}
            disabled={isScanning || anyUploading || selectedCompletedCount === 0}
            className="w-full sm:w-auto bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-8 py-3 rounded-xl flex items-center justify-center gap-2 text-sm transition-colors disabled:opacity-50 shadow-lg shadow-emerald-900/30 whitespace-nowrap"
          >
            <Play className="w-4 h-4 fill-current" />
            {isScanning ? 'Scanning Folders...' : 'Scan Now'}
          </button>
        </div>

        {errorMsg && <p className="text-xs text-red-400 mt-2">{errorMsg}</p>}

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
