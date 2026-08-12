import React, { useState, useEffect } from 'react';
import { ScanSession, AuditEvent } from '../types';
import { api } from '../services/api';
import { History, ShieldCheck, Clock, FileText } from 'lucide-react';

export const HistoryView: React.FC = () => {
  const [scans, setScans] = useState<ScanSession[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [scansData, auditData] = await Promise.all([
        api.getScanHistory(),
        api.getAuditLogs()
      ]);
      setScans(scansData);
      setAuditLogs(auditData);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <History className="w-5 h-5 text-emerald-400" />
          Scan History & Immutable Audit Logging
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Historical record of completed scans and security actions taken across the system.
        </p>
      </div>

      {/* Historical Scan Sessions */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm space-y-4 p-5">
        <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
          <Clock className="w-4 h-4 text-emerald-400" />
          Past Scan Sessions
        </h3>

        {loading ? (
          <div className="p-8 text-center text-slate-400 font-mono animate-pulse">Loading scan history...</div>
        ) : scans.length === 0 ? (
          <p className="text-xs text-slate-500 italic py-4">No historical scan sessions recorded.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950 text-slate-400 uppercase">
                <tr>
                  <th className="py-2.5 px-3">Scan ID</th>
                  <th className="py-2.5 px-3">Target Directory</th>
                  <th className="py-2.5 px-3">Started At</th>
                  <th className="py-2.5 px-3 text-center">Processed / Total</th>
                  <th className="py-2.5 px-3 text-center">Critical</th>
                  <th className="py-2.5 px-3 text-center">High</th>
                  <th className="py-2.5 px-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-slate-300">
                {scans.map(s => (
                  <tr key={s.scan_id} className="hover:bg-slate-800/40">
                    <td className="py-3 px-3 font-bold text-emerald-400">{s.scan_id}</td>
                    <td className="py-3 px-3 font-sans truncate max-w-xs">{s.root_path}</td>
                    <td className="py-3 px-3">{new Date(s.start_time).toLocaleString()}</td>
                    <td className="py-3 px-3 text-center">{s.processed_files} / {s.total_files}</td>
                    <td className="py-3 px-3 text-center text-red-400 font-bold">{s.critical_count}</td>
                    <td className="py-3 px-3 text-center text-orange-400 font-bold">{s.high_count}</td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        s.status === 'COMPLETED' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                      }`}>
                        {s.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Immutable Audit Log Stream */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-purple-400" />
          Audit Log Activity Stream
        </h3>

        <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 max-h-80 overflow-y-auto font-mono text-xs space-y-2">
          {auditLogs.length === 0 ? (
            <p className="text-slate-500 italic">No audit events logged yet.</p>
          ) : (
            auditLogs.map(a => (
              <div key={a.id} className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-900 pb-2 gap-1">
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 text-[10px]">{new Date(a.timestamp).toLocaleTimeString()}</span>
                  <span className="text-emerald-400 font-bold">[{a.action}]</span>
                  <span className="text-slate-300">{a.details || a.file_path || 'Action executed'}</span>
                </div>
                <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                  a.status === 'SUCCESS' ? 'text-emerald-400 bg-emerald-950/60' : 'text-red-400 bg-red-950/60'
                }`}>
                  {a.status}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
