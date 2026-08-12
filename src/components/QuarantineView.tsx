import React, { useState, useEffect } from 'react';
import { QuarantineItem } from '../types';
import { api } from '../services/api';
import { ShieldAlert, CloudCheck, CheckCircle2, AlertCircle, RefreshCw, Lock } from 'lucide-react';

export const QuarantineView: React.FC = () => {
  const [items, setItems] = useState<QuarantineItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadQuarantine();
  }, []);

  const loadQuarantine = async () => {
    try {
      setLoading(true);
      const data = await api.getQuarantineItems();
      setItems(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-purple-400" />
            Secure Cloud Quarantine & Verified Removal Vault
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Files uploaded to cloud storage and verified via SHA-256 before local disk deletion.
          </p>
        </div>
        <button
          onClick={loadQuarantine}
          className="p-2 bg-slate-900 border border-slate-800 rounded-lg text-slate-400 hover:text-slate-100 transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      <div className="bg-slate-900/60 border border-purple-500/20 p-4 rounded-xl text-xs text-purple-300 space-y-1">
        <span className="font-bold block">NON-NEGOTIABLE SAFETY GUARANTEE:</span>
        <p>
          Local file deletion ONLY occurs after remote cloud object presence and SHA-256 hash checksums are fully verified. If any step fails, the local file remains untouched.
        </p>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        {loading ? (
          <div className="p-12 text-center text-slate-400 font-mono animate-pulse">Loading vault items...</div>
        ) : items.length === 0 ? (
          <div className="p-12 text-center text-slate-500 italic">No files currently in quarantine vault.</div>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {items.map(item => (
              <div key={item.id} className="p-5 space-y-3 font-mono text-xs">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div>
                    <span className="font-bold text-slate-200 text-sm font-sans">{item.filename}</span>
                    <span className="text-slate-500 block text-[11px] mt-0.5">{item.original_path}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className={`px-2.5 py-1 rounded text-[11px] font-bold border ${
                      item.upload_status === 'UPLOADED' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                    }`}>
                      Upload: {item.upload_status}
                    </span>

                    <span className={`px-2.5 py-1 rounded text-[11px] font-bold border ${
                      item.verification_status === 'VERIFIED' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-red-500/10 text-red-400 border-red-500/30'
                    }`}>
                      Verify: {item.verification_status}
                    </span>

                    <span className={`px-2.5 py-1 rounded text-[11px] font-bold border ${
                      item.deletion_status === 'DELETED' ? 'bg-red-500/10 text-red-400 border-red-500/30' : 'bg-slate-800 text-slate-400 border-slate-700'
                    }`}>
                      Local Disk: {item.deletion_status}
                    </span>
                  </div>
                </div>

                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1 text-slate-400 text-[11px]">
                  <div>Cloud Object: <span className="text-slate-200">{item.cloud_object || 'N/A'}</span></div>
                  <div>SHA-256 Hash: <span className="text-slate-200">{item.sha256}</span></div>
                  <div>Quarantined At: <span className="text-slate-200">{new Date(item.quarantined_at).toLocaleString()}</span></div>
                </div>

                {item.logs && item.logs.length > 0 && (
                  <div className="bg-slate-950/80 p-2.5 rounded border border-slate-800/80 space-y-1 text-[10px] text-slate-400 max-h-32 overflow-y-auto">
                    {item.logs.map((log, idx) => (
                      <div key={idx}>{log}</div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
