import React, { useState, useEffect, useRef } from 'react';
import { FileItem } from '../types';
import { api } from '../services/api';
import { ClassificationBadge } from './Badges';
import { Search, Filter, FileText, ChevronRight, Upload, CheckCircle2, AlertTriangle, XCircle, RefreshCw } from 'lucide-react';

interface FilesViewProps {
  onSelectFile: (fileId: string) => void;
}

export const FilesView: React.FC<FilesViewProps> = ({ onSelectFile }) => {
  const [files, setFiles] = useState<FileItem[]>([]);
  const [cloudUploads, setCloudUploads] = useState<Record<string, any>>({});
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedClassification, setSelectedClassification] = useState<string>('ALL');
  const [selectedExt, setSelectedExt] = useState<string>('ALL');
  const [selectedFileIds, setSelectedFileIds] = useState<Set<string>>(new Set());
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<{ current: number; total: number; message: string } | null>(null);
  const [showUploadAllModal, setShowUploadAllModal] = useState(false);
  const masterCheckboxRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    loadFilesAndUploads();
  }, []);

  const loadFilesAndUploads = async () => {
    try {
      setLoading(true);
      const fileData = await api.getFiles();
      const uploadData = (await api.getCloudUploads().catch(() => [])) as any[];
      setFiles(fileData);
      const map: Record<string, any> = {};
      if (Array.isArray(uploadData)) {
        for (const u of uploadData) {
          map[u.file_id] = u;
        }
      }
      setCloudUploads(map);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const filteredFiles = files.filter(f => {
    const matchesSearch =
      f.filename.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.path.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.sha256.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesClass =
      selectedClassification === 'ALL' || f.classification === selectedClassification;

    const matchesExt =
      selectedExt === 'ALL' || f.extension.toLowerCase() === selectedExt.toLowerCase();

    return matchesSearch && matchesClass && matchesExt;
  });

  // Select All indeterminate state handling
  const allFilteredSelected = filteredFiles.length > 0 && filteredFiles.every(f => selectedFileIds.has(f.file_id));
  const someFilteredSelected = filteredFiles.some(f => selectedFileIds.has(f.file_id)) && !allFilteredSelected;

  useEffect(() => {
    if (masterCheckboxRef.current) {
      masterCheckboxRef.current.indeterminate = someFilteredSelected;
    }
  }, [someFilteredSelected]);

  const handleToggleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    const checked = e.target.checked;
    const newSelected = new Set(selectedFileIds);
    if (checked) {
      filteredFiles.forEach(f => newSelected.add(f.file_id));
    } else {
      filteredFiles.forEach(f => newSelected.delete(f.file_id));
    }
    setSelectedFileIds(newSelected);
  };

  const handleToggleSelectOne = (fileId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const newSelected = new Set(selectedFileIds);
    if (newSelected.has(fileId)) {
      newSelected.delete(fileId);
    } else {
      newSelected.add(fileId);
    }
    setSelectedFileIds(newSelected);
  };

  const handleUploadSelected = async () => {
    if (selectedFileIds.size === 0) return;
    try {
      setUploading(true);
      const fileIdsArray: string[] = Array.from(selectedFileIds);
      setUploadProgress({ current: 0, total: fileIdsArray.length, message: 'Initiating cloud upload...' });

      const res = await api.uploadSelectedFiles(fileIdsArray);
      await loadFilesAndUploads();
      setUploadProgress({ current: fileIdsArray.length, total: fileIdsArray.length, message: `Upload completed: ${res.success_count} success, ${res.failed_count} failed.` });
    } catch (e: any) {
      console.error(e);
      alert('Upload failed: ' + (e.message || 'Unknown error'));
    } finally {
      setUploading(false);
      setTimeout(() => setUploadProgress(null), 4000);
    }
  };

  const handleUploadAll = async () => {
    setShowUploadAllModal(false);
    try {
      setUploading(true);
      setUploadProgress({ current: 0, total: files.length, message: 'Uploading all scanned files...' });

      const res = await api.uploadAllFiles();
      await loadFilesAndUploads();
      setUploadProgress({ current: files.length, total: files.length, message: `Upload All completed: ${res.success_count} success, ${res.failed_count} failed.` });
    } catch (e: any) {
      console.error(e);
      alert('Upload All failed: ' + (e.message || 'Unknown error'));
    } finally {
      setUploading(false);
      setTimeout(() => setUploadProgress(null), 4000);
    }
  };

  const handleRetryUpload = async (fileId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      setUploading(true);
      await api.retryCloudUpload(fileId);
      await loadFilesAndUploads();
    } catch (e: any) {
      console.error(e);
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FileText className="w-5 h-5 text-emerald-400" />
            Scanned Files & Cloud Upload Vault
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Browse static inspection results, SHA-256 fingerprints, and perform non-destructive cloud quarantine uploads.
          </p>
        </div>

        {/* Action Bar */}
        <div className="flex items-center gap-3">
          <span className="text-xs font-mono text-slate-400">
            {selectedFileIds.size} file{selectedFileIds.size === 1 ? '' : 's'} selected
          </span>
          <button
            onClick={handleUploadSelected}
            disabled={selectedFileIds.size === 0 || uploading}
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-800 disabled:text-slate-600 disabled:cursor-not-allowed text-white rounded-lg text-xs font-bold font-mono transition-colors flex items-center gap-2 shadow-sm"
          >
            <Upload className="w-3.5 h-3.5" />
            Upload Selected
          </button>
          <button
            onClick={() => setShowUploadAllModal(true)}
            disabled={uploading || files.length === 0}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 disabled:bg-slate-900 disabled:text-slate-600 text-slate-200 rounded-lg text-xs font-bold font-mono transition-colors flex items-center gap-2 border border-slate-700"
          >
            <Upload className="w-3.5 h-3.5" />
            Upload All ({files.length})
          </button>
        </div>
      </div>

      {/* Upload Progress Banner */}
      {uploadProgress && (
        <div className="bg-slate-900 border border-emerald-500/40 p-4 rounded-xl flex items-center justify-between gap-4 animate-fade-in shadow-lg">
          <div className="space-y-1">
            <div className="text-xs font-mono text-emerald-400 font-bold flex items-center gap-2">
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              {uploadProgress.message}
            </div>
            <div className="w-64 bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
              <div
                className="bg-emerald-500 h-full transition-all duration-300"
                style={{ width: `${(uploadProgress.current / (uploadProgress.total || 1)) * 100}%` }}
              />
            </div>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {uploadProgress.current} / {uploadProgress.total} processed
          </span>
        </div>
      )}

      {/* Filter bar */}
      <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex flex-wrap gap-4 items-center justify-between">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
          <input
            type="text"
            placeholder="Search by filename, path, or SHA-256..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500 font-mono"
          />
        </div>

        <div className="flex flex-wrap gap-3 items-center">
          {/* Classification Filter */}
          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={selectedClassification}
              onChange={e => setSelectedClassification(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
            >
              <option value="ALL">All Classifications</option>
              <option value="RESTRICTED">RESTRICTED</option>
              <option value="CONFIDENTIAL">CONFIDENTIAL</option>
              <option value="INTERNAL">INTERNAL</option>
              <option value="PUBLIC">PUBLIC</option>
            </select>
          </div>

          {/* Format Filter */}
          <select
            value={selectedExt}
            onChange={e => setSelectedExt(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
          >
            <option value="ALL">All File Types</option>
            <option value=".xlsx">.xlsx</option>
            <option value=".csv">.csv</option>
            <option value=".docx">.docx</option>
            <option value=".txt">.txt</option>
            <option value=".pptx">.pptx</option>
            <option value=".pdf">.pdf</option>
          </select>
        </div>
      </div>

      {/* Files Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        {loading ? (
          <div className="p-12 text-center text-slate-400 animate-pulse font-mono text-sm">
            Fetching file inventory...
          </div>
        ) : filteredFiles.length === 0 ? (
          <div className="p-12 text-center text-slate-500 italic">
            No scanned files match the selected filter criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-xs text-slate-400 font-mono uppercase">
                <tr>
                  <th className="py-3.5 px-4 w-10">
                    <input
                      type="checkbox"
                      ref={masterCheckboxRef}
                      checked={allFilteredSelected}
                      onChange={handleToggleSelectAll}
                      className="rounded bg-slate-950 border-slate-700 text-emerald-500 focus:ring-0 cursor-pointer"
                    />
                  </th>
                  <th className="py-3.5 px-4 font-semibold">Filename & Path</th>
                  <th className="py-3.5 px-4 font-semibold">Classification</th>
                  <th className="py-3.5 px-4 font-semibold text-center">Risk Score</th>
                  <th className="py-3.5 px-4 font-semibold">Cloud Status</th>
                  <th className="py-3.5 px-4 font-semibold">Size</th>
                  <th className="py-3.5 px-4 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {filteredFiles.map(f => {
                  const uploadInfo = cloudUploads[f.file_id];
                  const isSelected = selectedFileIds.has(f.file_id);

                  return (
                    <tr
                      key={f.file_id}
                      onClick={() => onSelectFile(f.file_id)}
                      className={`hover:bg-slate-800/50 cursor-pointer transition-colors ${isSelected ? 'bg-emerald-950/10' : ''}`}
                    >
                      <td className="py-3.5 px-4" onClick={e => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={(e) => {
                            const newSelected = new Set(selectedFileIds);
                            if (e.target.checked) newSelected.add(f.file_id);
                            else newSelected.delete(f.file_id);
                            setSelectedFileIds(newSelected);
                          }}
                          className="rounded bg-slate-950 border-slate-700 text-emerald-500 focus:ring-0 cursor-pointer"
                        />
                      </td>
                      <td className="py-3.5 px-4 max-w-sm">
                        <div className="font-semibold text-slate-200 font-mono text-sm">{f.filename}</div>
                        <div className="text-xs text-slate-500 font-mono truncate mt-0.5">{f.path}</div>
                      </td>
                      <td className="py-3.5 px-4">
                        <ClassificationBadge classification={f.classification} />
                      </td>
                      <td className="py-3.5 px-4 text-center">
                        <div className="inline-flex items-center gap-1.5 font-mono font-bold text-sm">
                          <span className={f.risk_score >= 80 ? 'text-red-400' : f.risk_score >= 50 ? 'text-orange-400' : f.risk_score >= 20 ? 'text-amber-300' : 'text-emerald-400'}>
                            {f.risk_score}
                          </span>
                          <span className="text-xs text-slate-600 font-normal">/ 100</span>
                        </div>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-xs">
                        {!uploadInfo || uploadInfo.upload_status === 'NOT_UPLOADED' ? (
                          <span className="text-slate-500">Not uploaded</span>
                        ) : uploadInfo.upload_status === 'UPLOADING' ? (
                          <span className="text-amber-400 flex items-center gap-1">
                            <RefreshCw className="w-3 h-3 animate-spin" /> Uploading...
                          </span>
                        ) : uploadInfo.upload_status === 'UPLOADED' || uploadInfo.upload_status === 'ALREADY_UPLOADED' ? (
                          <div className="space-y-0.5">
                            <span className="text-emerald-400 font-bold flex items-center gap-1">
                              <CheckCircle2 className="w-3 h-3" /> {uploadInfo.upload_status === 'ALREADY_UPLOADED' ? 'Already uploaded' : 'Uploaded'}
                            </span>
                            <div className="text-[10px] text-slate-400">SHA-256 verified</div>
                            <div className="text-[10px] text-emerald-500/80">Local file retained</div>
                          </div>
                        ) : uploadInfo.upload_status === 'VERIFICATION_FAILED' ? (
                          <div className="space-y-1">
                            <span className="text-red-400 font-bold flex items-center gap-1">
                              <AlertTriangle className="w-3 h-3" /> Verification failed
                            </span>
                            <button
                              onClick={(e) => handleRetryUpload(f.file_id, e)}
                              className="px-2 py-0.5 bg-red-950 text-red-300 border border-red-800 rounded text-[10px] hover:bg-red-900"
                            >
                              Retry
                            </button>
                          </div>
                        ) : (
                          <div className="space-y-1">
                            <span className="text-red-400 font-bold flex items-center gap-1">
                              <XCircle className="w-3 h-3" /> Upload failed
                            </span>
                            <button
                              onClick={(e) => handleRetryUpload(f.file_id, e)}
                              className="px-2 py-0.5 bg-red-950 text-red-300 border border-red-800 rounded text-[10px] hover:bg-red-900"
                            >
                              Retry
                            </button>
                          </div>
                        )}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-xs text-slate-400">
                        {(f.size / 1024).toFixed(1)} KB
                      </td>
                      <td className="py-3.5 px-4 text-right text-slate-500">
                        <ChevronRight className="w-4 h-4 ml-auto" />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Upload All Confirmation Modal */}
      {showUploadAllModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <Upload className="w-5 h-5 text-emerald-400" />
              Upload All Scanned Files?
            </h3>
            <p className="text-sm text-slate-300">
              Upload all <span className="font-bold text-slate-100">{files.length}</span> scanned files to cloud storage.
            </p>
            <div className="bg-emerald-950/30 border border-emerald-500/30 p-3 rounded-lg text-xs text-emerald-300 font-mono">
              <strong>HARD GUARANTEE:</strong> Local files will NOT be deleted. They will remain fully intact on your system.
            </div>
            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setShowUploadAllModal(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-mono font-bold transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleUploadAll}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-mono font-bold transition-colors shadow-sm"
              >
                Upload All
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
