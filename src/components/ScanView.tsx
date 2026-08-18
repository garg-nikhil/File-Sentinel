import React, { useState, useEffect, useRef } from 'react';
import { ScanSession, FileItem } from '../types';
import { api } from '../services/api';
import { useToast } from '../context/ToastContext';
import { 
  FolderSearch, Play, Pause, RefreshCw, CheckCircle2, AlertTriangle, 
  ShieldCheck, UploadCloud, Folder, Trash2, CheckSquare, Square, 
  FileText, Search, Clock, PauseCircle, AlertCircle, CheckCircle, FileCode,
  RotateCcw
} from 'lucide-react';

interface ScanViewProps {
  onScanComplete: (scanId: string) => void;
  activeScan: ScanSession | null;
  setActiveScan: (scan: ScanSession | null) => void;
  isScanLocked?: boolean;
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
  setActiveScan,
  isScanLocked = false
}) => {
  const { showToast } = useToast();
  const [uploadedFolders, setUploadedFolders] = useState<UploadedFolder[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [isPausing, setIsPausing] = useState(false);
  const [isResuming, setIsResuming] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [scanFiles, setScanFiles] = useState<FileItem[]>([]);
  const [recentScans, setRecentScans] = useState<ScanSession[]>([]);
  const [fileFilter, setFileFilter] = useState<'ALL' | 'COMPLETED' | 'PENDING' | 'ERROR'>('ALL');
  const [fileSearch, setFileSearch] = useState('');

  const fileInputRef = useRef<HTMLInputElement>(null);
  const alertedFilesRef = useRef<Set<string>>(new Set());
  const alertedCompletionsRef = useRef<Set<string>>(new Set());

  // Load scan history to identify interrupted / paused scans
  const loadScanHistory = async () => {
    try {
      const history = await api.getScanHistory();
      setRecentScans(history);
    } catch (e) {
      console.warn('Failed to fetch scan history', e);
    }
  };

  useEffect(() => {
    loadScanHistory();
  }, []);

  // Poll scan progress and fetch individual file statuses when a scan is active
  useEffect(() => {
    let timer: any;
    let fileTimer: any;

    const fetchFiles = async (scanId: string) => {
      try {
        const files = await api.getScanFiles(scanId);
        setScanFiles(files);

        // Real-time security violation detection
        for (const f of files) {
          if (!alertedFilesRef.current.has(f.file_id)) {
            const critCount = f.findings_count?.critical || 0;
            const highCount = f.findings_count?.high || 0;
            const isErr = f.scan_status === 'ERROR';

            if (critCount > 0 || highCount > 0 || isErr) {
              alertedFilesRef.current.add(f.file_id);
              showToast({
                title: critCount > 0 ? 'CRITICAL SECURITY VIOLATION' : isErr ? 'FILE SCANNING ERROR' : 'HIGH RISK FINDING DETECTED',
                message: `File "${f.filename}" encountered ${critCount > 0 ? 'Critical PII or API secret violation' : isErr ? 'analyzer execution error' : 'high risk compliance issue'}.`,
                type: critCount > 0 || isErr ? 'violation' : 'warning',
                fileId: f.file_id,
                filePath: f.path,
                scanId: scanId,
                actionLabel: 'Inspect File Details'
              });
            }
          }
        }
      } catch (e) {
        console.warn('Failed to fetch scan files:', e);
      }
    };

    if (activeScan) {
      fetchFiles(activeScan.scan_id);

      if (activeScan.status === 'SCANNING') {
        setIsScanning(true);
        timer = setInterval(async () => {
          try {
            const updated = await api.getScanProgress(activeScan.scan_id);
            setActiveScan(updated);
            if (updated.status === 'COMPLETED' || updated.status === 'FAILED') {
              setIsScanning(false);
              clearInterval(timer);
              clearInterval(fileTimer);
              fetchFiles(updated.scan_id);
              loadScanHistory();

              if (!alertedCompletionsRef.current.has(updated.scan_id)) {
                alertedCompletionsRef.current.add(updated.scan_id);
                if (updated.status === 'COMPLETED') {
                  const critCount = updated.critical_count || 0;
                  const highCount = updated.high_count || 0;
                  const durationMs = updated.end_time && updated.start_time
                    ? Math.max(0, new Date(updated.end_time).getTime() - new Date(updated.start_time).getTime())
                    : 0;
                  showToast({
                    title: 'SCAN SESSION COMPLETED SUCCESSFULLY',
                    message: `Analyzed ${updated.total_files || 0} files${durationMs ? ` in ${durationMs}ms` : ''}. ${critCount} critical violations and ${highCount} high risk findings flagged.`,
                    type: critCount > 0 ? 'warning' : 'success',
                    scanId: updated.scan_id,
                    actionLabel: 'View Audit Compliance Report',
                    onAction: () => onScanComplete(updated.scan_id)
                  });
                  onScanComplete(updated.scan_id);
                } else if (updated.status === 'FAILED') {
                  showToast({
                    title: 'SCAN SESSION TERMINATED WITH ERROR',
                    message: `Scan execution failed due to an error encountered during analysis.`,
                    type: 'violation',
                    scanId: updated.scan_id
                  });
                }
              }
            }
          } catch (e) {
            console.error(e);
          }
        }, 500);

        fileTimer = setInterval(() => {
          fetchFiles(activeScan.scan_id);
        }, 1000);
      } else {
        setIsScanning(false);
      }
    }

    return () => {
      if (timer) clearInterval(timer);
      if (fileTimer) clearInterval(fileTimer);
    };
  }, [activeScan?.scan_id, activeScan?.status]);

  const handleStartScan = async () => {
    if (isScanLocked) {
      setErrorMsg('Scanning is locked due to detected system clock manipulation.');
      showToast({
        title: 'SCAN ACTION BLOCKED',
        message: 'A system clock drift or manual modification has been detected. Scanning is disabled until revalidation.',
        type: 'violation'
      });
      return;
    }
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
      setScanFiles([]);
      showToast({
        title: 'LONG-RUNNING SCAN INITIATED',
        message: `Analysis engine initialized across ${paths.length} folder root(s). Listening for real-time compliance findings...`,
        type: 'info',
        scanId: session.scan_id
      });
    } catch (err: any) {
      setIsScanning(false);
      setErrorMsg(err.message || 'Failed to initialize scan engine');
      showToast({
        title: 'SCAN INITIATION ERROR',
        message: err.message || 'Failed to start security scan session',
        type: 'violation'
      });
    }
  };

  const handlePauseScan = async () => {
    if (!activeScan) return;
    try {
      setErrorMsg(null);
      setIsPausing(true);
      const res = await api.pauseScan(activeScan.scan_id);
      setActiveScan(res.scan);
      setIsScanning(false);
      loadScanHistory();
      showToast({
        title: 'SCAN SESSION PAUSED',
        message: `Scan execution checkpoint saved locally. Resume anytime from the Scanner panel.`,
        type: 'warning',
        scanId: activeScan.scan_id
      });
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to pause scan session');
    } finally {
      setIsPausing(false);
    }
  };

  const handleResumeScan = async (scanIdToResume?: string) => {
    if (isScanLocked) {
      setErrorMsg('Scanning is locked due to detected system clock manipulation.');
      showToast({
        title: 'SCAN ACTION BLOCKED',
        message: 'A system clock drift or manual modification has been detected. Scanning is disabled until revalidation.',
        type: 'violation'
      });
      return;
    }
    const targetId = scanIdToResume || activeScan?.scan_id;
    if (!targetId) return;

    try {
      setErrorMsg(null);
      setIsResuming(true);
      setIsScanning(true);
      const session = await api.resumeScan(targetId);
      setActiveScan(session);
      loadScanHistory();
      showToast({
        title: 'SCAN SESSION RESUMED',
        message: `Resumed scan processing from saved checkpoint. Monitoring file violations in real-time...`,
        type: 'info',
        scanId: targetId
      });
    } catch (err: any) {
      setIsScanning(false);
      setErrorMsg(err.message || 'Failed to resume scan session');
      showToast({
        title: 'SCAN RESUME ERROR',
        message: err.message || 'Failed to resume interrupted scan session',
        type: 'violation'
      });
    } finally {
      setIsResuming(false);
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

  const formatFileSize = (bytes: number) => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const progressPercent = activeScan && activeScan.total_files > 0
    ? Math.round((activeScan.processed_files / activeScan.total_files) * 100)
    : 0;

  const anyUploading = uploadedFolders.some(f => f.status === 'uploading');
  const selectedCompletedCount = uploadedFolders.filter(f => f.selected && f.status === 'completed').length;

  // Filter scan files
  const filteredFiles = scanFiles.filter(file => {
    const matchesSearch = !fileSearch || 
      file.filename.toLowerCase().includes(fileSearch.toLowerCase()) || 
      file.path.toLowerCase().includes(fileSearch.toLowerCase());
    
    if (!matchesSearch) return false;

    if (fileFilter === 'COMPLETED') return file.scan_status === 'SUCCESS';
    if (fileFilter === 'PENDING') return file.scan_status === 'PENDING' || file.scan_status === 'PROCESSING';
    if (fileFilter === 'ERROR') return file.scan_status === 'ERROR' || file.scan_status === 'SKIPPED';
    return true;
  });

  // Find interrupted / resumable scans from history
  const resumableScans = recentScans.filter(
    s => s.status === 'PAUSED' || s.status === 'CANCELLED' || (s.status === 'SCANNING' && s.scan_id !== activeScan?.scan_id) || (s.processed_files < s.total_files && s.status !== 'COMPLETED')
  );

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-8">
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <FolderSearch className="w-5 h-5 text-emerald-400" />
          Target Folder Selection & Resumable Scan Engine
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Select target directories, execute scans with real-time file status tracking, and seamlessly resume interrupted scan jobs.
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
                        <span className="text-slate-300 font-semibold flex-shrink-0">• {folder.fileCount} files uploaded</span>
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

        {/* SCAN EXECUTION BUTTON */}
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

        {/* Supported Formats */}
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

      {/* Interrupted & Resumable Scans Panel */}
      {resumableScans.length > 0 && (
        <div className="bg-slate-900 border border-amber-500/30 rounded-xl p-6 space-y-4 shadow-lg shadow-amber-950/10">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <RotateCcw className="w-5 h-5 text-amber-400" />
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
                Interrupted / Resumable Scan Jobs ({resumableScans.length})
              </h3>
            </div>
            <span className="text-xs text-amber-400/80 font-mono">
              Database persistence enables zero-loss restart from last saved file
            </span>
          </div>

          <div className="space-y-3">
            {resumableScans.map(s => {
              const pct = s.total_files > 0 ? Math.round((s.processed_files / s.total_files) * 100) : 0;
              return (
                <div key={s.scan_id} className="bg-slate-950 border border-slate-800 p-4 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-emerald-400 font-bold">{s.scan_id}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                        s.status === 'PAUSED' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' : 'bg-slate-800 text-slate-300 border-slate-700'
                      }`}>
                        {s.status}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 font-mono truncate">{s.root_path}</p>
                    <p className="text-[11px] text-slate-500 font-mono">
                      Progress: {s.processed_files} / {s.total_files} files ({pct}%) • Started: {new Date(s.start_time).toLocaleString()}
                    </p>
                  </div>

                  <button
                    onClick={() => handleResumeScan(s.scan_id)}
                    disabled={isScanning || isResuming}
                    className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs px-5 py-2.5 rounded-lg flex items-center justify-center gap-2 transition-colors shadow-sm disabled:opacity-50 whitespace-nowrap self-start md:self-center"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${isResuming ? 'animate-spin' : ''}`} />
                    {isResuming ? 'Resuming...' : 'Resume Scan Job'}
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Real-time Scan Progress Section */}
      {activeScan && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                {activeScan.status === 'SCANNING' ? (
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-400 animate-ping"></span>
                ) : activeScan.status === 'PAUSED' ? (
                  <PauseCircle className="w-5 h-5 text-amber-400" />
                ) : (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                )}
                Scan Session: <span className="font-mono text-emerald-400">{activeScan.scan_id}</span>
              </h3>
              <p className="text-xs text-slate-400 mt-1 font-mono">{activeScan.root_path}</p>
            </div>

            <div className="flex items-center gap-3">
              <span className={`px-3 py-1 rounded-full text-xs font-mono font-bold border ${
                activeScan.status === 'SCANNING' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' :
                activeScan.status === 'PAUSED' ? 'bg-amber-500/20 text-amber-300 border-amber-500/50' :
                'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
              }`}>
                {activeScan.status}
              </span>

              {/* Pause / Resume Actions */}
              {activeScan.status === 'SCANNING' && (
                <button
                  onClick={handlePauseScan}
                  disabled={isPausing}
                  className="bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/40 text-xs px-4 py-2 rounded-lg flex items-center gap-2 font-medium transition-colors disabled:opacity-50"
                >
                  <Pause className="w-3.5 h-3.5" />
                  {isPausing ? 'Pausing...' : 'Pause Scan'}
                </button>
              )}

              {(activeScan.status === 'PAUSED' || activeScan.status === 'CANCELLED' || (activeScan.status !== 'SCANNING' && activeScan.processed_files < activeScan.total_files)) && (
                <button
                  onClick={() => handleResumeScan()}
                  disabled={isResuming}
                  className="bg-emerald-600 hover:bg-emerald-500 text-white border border-emerald-500/40 text-xs px-4 py-2 rounded-lg flex items-center gap-2 font-medium transition-colors shadow-sm disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isResuming ? 'animate-spin' : ''}`} />
                  {isResuming ? 'Resuming...' : 'Resume Scan'}
                </button>
              )}
            </div>
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
                  className={`h-full rounded-full transition-all duration-300 ${
                    activeScan.status === 'PAUSED' ? 'bg-amber-500' : 'bg-gradient-to-r from-emerald-600 to-emerald-400'
                  }`}
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

          {/* Real-time Individual File Status Persistence List */}
          <div className="space-y-4 pt-4 border-t border-slate-800">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <FileText className="w-4 h-4 text-emerald-400" />
                  Individual File Persistence Status ({scanFiles.length} tracked)
                </h4>
                <p className="text-xs text-slate-400 mt-0.5">
                  Every file state is saved in the SQLite database to allow instant resumption.
                </p>
              </div>

              {/* Filter Tabs */}
              <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
                {(['ALL', 'COMPLETED', 'PENDING', 'ERROR'] as const).map(tab => (
                  <button
                    key={tab}
                    onClick={() => setFileFilter(tab)}
                    className={`px-3 py-1 rounded font-mono font-medium transition-colors ${
                      fileFilter === tab ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {tab}
                  </button>
                ))}
              </div>
            </div>

            {/* Search Input */}
            <div className="relative">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search tracked file name or path..."
                value={fileSearch}
                onChange={e => setFileSearch(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 font-mono"
              />
            </div>

            {/* File List Table */}
            {filteredFiles.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 bg-slate-950/40 rounded-xl border border-slate-800/80">
                {scanFiles.length === 0 ? 'Discovering and saving file records to database...' : 'No files matching current filter/search.'}
              </div>
            ) : (
              <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-950/60 max-h-80 overflow-y-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-900 border-b border-slate-800 text-slate-400 font-semibold sticky top-0">
                    <tr>
                      <th className="p-3">File Name & Path</th>
                      <th className="p-3">Status</th>
                      <th className="p-3">Size</th>
                      <th className="p-3">Classification</th>
                      <th className="p-3">Findings</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {filteredFiles.map(file => (
                      <tr key={file.file_id || file.path} className="hover:bg-slate-900/50 transition-colors">
                        <td className="p-3 max-w-xs truncate" title={file.path}>
                          <div className="font-semibold text-slate-200 truncate">{file.filename}</div>
                          <div className="text-[11px] text-slate-500 truncate">{file.path}</div>
                        </td>
                        <td className="p-3 whitespace-nowrap">
                          {file.scan_status === 'SUCCESS' && (
                            <span className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10px] font-bold inline-flex items-center gap-1">
                              <CheckCircle className="w-3 h-3" /> Completed
                            </span>
                          )}
                          {file.scan_status === 'PROCESSING' && (
                            <span className="px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-400 text-[10px] font-bold inline-flex items-center gap-1 animate-pulse">
                              <RefreshCw className="w-3 h-3 animate-spin" /> Processing
                            </span>
                          )}
                          {file.scan_status === 'PENDING' && (
                            <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-400 text-[10px] font-bold inline-flex items-center gap-1">
                              <Clock className="w-3 h-3" /> Pending
                            </span>
                          )}
                          {file.scan_status === 'ERROR' && (
                            <span className="px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-400 text-[10px] font-bold inline-flex items-center gap-1">
                              <AlertCircle className="w-3 h-3" /> Error
                            </span>
                          )}
                          {file.scan_status === 'SKIPPED' && (
                            <span className="px-2 py-0.5 rounded bg-purple-500/10 border border-purple-500/30 text-purple-400 text-[10px] font-bold inline-flex items-center gap-1">
                              Skipped
                            </span>
                          )}
                        </td>
                        <td className="p-3 text-slate-400 whitespace-nowrap">
                          {formatFileSize(file.size)}
                        </td>
                        <td className="p-3 whitespace-nowrap">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            file.classification === 'RESTRICTED' ? 'bg-red-500/10 text-red-400 border-red-500/30' :
                            file.classification === 'CONFIDENTIAL' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' :
                            file.classification === 'INTERNAL' ? 'bg-blue-500/10 text-blue-400 border-blue-500/30' :
                            'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          }`}>
                            {file.classification}
                          </span>
                        </td>
                        <td className="p-3 text-slate-300 font-semibold whitespace-nowrap">
                          {file.findings && file.findings.length > 0 ? (
                            <span className="text-amber-400">{file.findings.length} findings</span>
                          ) : (
                            <span className="text-slate-500">0</span>
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
