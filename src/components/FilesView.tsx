import React, { useState, useEffect } from 'react';
import { FileItem, Classification } from '../types';
import { api } from '../services/api';
import { SeverityBadge, ClassificationBadge } from './Badges';
import { Search, Filter, FileText, ArrowUpDown, ChevronRight } from 'lucide-react';

interface FilesViewProps {
  onSelectFile: (fileId: string) => void;
}

export const FilesView: React.FC<FilesViewProps> = ({ onSelectFile }) => {
  const [files, setFiles] = useState<FileItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedClassification, setSelectedClassification] = useState<string>('ALL');
  const [selectedExt, setSelectedExt] = useState<string>('ALL');

  useEffect(() => {
    loadFiles();
  }, []);

  const loadFiles = async () => {
    try {
      setLoading(true);
      const data = await api.getFiles();
      setFiles(data);
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

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FileText className="w-5 h-5 text-emerald-400" />
            Scanned Files & Compliance Index
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Browse static inspection results, SHA-256 fingerprints, risk scores, and classification tags.
          </p>
        </div>
      </div>

      {/* Filter bar */}
      <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex flex-wrap gap-4 items-center justify-between">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
          <input
            type="text"
            placeholder="Search by filename, path, or SHA-256..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
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
                  <th className="py-3.5 px-4 font-semibold">Filename & Path</th>
                  <th className="py-3.5 px-4 font-semibold">Classification</th>
                  <th className="py-3.5 px-4 font-semibold text-center">Risk Score</th>
                  <th className="py-3.5 px-4 font-semibold">SHA-256</th>
                  <th className="py-3.5 px-4 font-semibold">Size</th>
                  <th className="py-3.5 px-4 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {filteredFiles.map(f => (
                  <tr
                    key={f.file_id}
                    onClick={() => onSelectFile(f.file_id)}
                    className="hover:bg-slate-800/50 cursor-pointer transition-colors"
                  >
                    <td className="py-3.5 px-4 max-w-md">
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
                    <td className="py-3.5 px-4 font-mono text-xs text-slate-400">
                      {f.sha256.substring(0, 12)}...
                    </td>
                    <td className="py-3.5 px-4 font-mono text-xs text-slate-400">
                      {(f.size / 1024).toFixed(1)} KB
                    </td>
                    <td className="py-3.5 px-4 text-right text-slate-500">
                      <ChevronRight className="w-4 h-4 ml-auto" />
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
