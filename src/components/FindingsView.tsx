import React, { useState, useEffect } from 'react';
import { Finding } from '../types';
import { api } from '../services/api';
import { SeverityBadge } from './Badges';
import { AlertTriangle, Search, Filter } from 'lucide-react';

export const FindingsView: React.FC = () => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');

  useEffect(() => {
    loadFindings();
  }, []);

  const loadFindings = async () => {
    try {
      setLoading(true);
      const data = await api.getFindings();
      setFindings(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const filtered = findings.filter(f => {
    const matchesSearch =
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.description.toLowerCase().includes(search.toLowerCase()) ||
      ((f as any).filename || '').toLowerCase().includes(search.toLowerCase());

    const matchesSev = selectedSeverity === 'ALL' || f.severity === selectedSeverity;

    return matchesSearch && matchesSev;
  });

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-amber-400" />
          Findings & Policy Violations Log
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Normalized risk findings across all scanned local files.
        </p>
      </div>

      {/* Filter controls */}
      <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex flex-wrap gap-4 items-center justify-between">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
          <input
            type="text"
            placeholder="Search findings title, description, or filename..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-slate-400" />
          <select
            value={selectedSeverity}
            onChange={e => setSelectedSeverity(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {loading ? (
          <div className="p-12 text-center text-slate-400 font-mono animate-pulse">Loading DLP findings...</div>
        ) : filtered.length === 0 ? (
          <div className="p-12 text-center text-slate-500 italic bg-slate-900 border border-slate-800 rounded-xl">
            No DLP findings recorded.
          </div>
        ) : (
          filtered.map(f => (
            <div key={f.finding_id} className="bg-slate-900 border border-slate-800 p-5 rounded-xl space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={f.severity} />
                  <h3 className="text-sm font-bold text-slate-100">{f.title}</h3>
                  <span className="text-xs font-mono text-slate-500">[{f.rule_id}]</span>
                </div>
                <div className="text-xs font-mono text-emerald-400 font-semibold bg-slate-950 px-2.5 py-1 rounded border border-slate-800">
                  File: {(f as any).filename || f.file_id}
                </div>
              </div>

              <p className="text-xs text-slate-300">{f.description}</p>

              {f.evidence?.snippet && (
                <div className="bg-slate-950 p-2.5 rounded border border-slate-800 text-xs font-mono text-amber-300 break-all">
                  {f.evidence.snippet}
                </div>
              )}

              <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1">
                <span>Category: <strong className="text-slate-400">{f.category}</strong></span>
                <span>Source: <strong className="text-slate-400">{f.source}</strong></span>
                <span>Confidence: <strong className="text-slate-400">{(f.confidence * 100).toFixed(0)}%</strong></span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
