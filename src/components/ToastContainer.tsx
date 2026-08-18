import React from 'react';
import { useToast } from '../context/ToastContext';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  CheckCircle2, 
  Info, 
  X, 
  ExternalLink, 
  Bell, 
  Trash2, 
  Clock, 
  Check 
} from 'lucide-react';

export const ToastContainer: React.FC = () => {
  const { toasts, dismissToast } = useToast();

  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-3 max-w-md w-full pointer-events-none px-4">
      {toasts.map(toast => (
        <div
          key={toast.id}
          className={`pointer-events-auto relative overflow-hidden rounded-xl border p-4 shadow-2xl backdrop-blur-md transition-all duration-300 animate-in slide-in-from-bottom-5 fade-in-20 ${
            toast.type === 'violation'
              ? 'bg-slate-950/95 border-rose-600/90 text-slate-100 shadow-rose-950/50 shadow-2xl ring-1 ring-rose-500/30'
              : toast.type === 'warning'
              ? 'bg-slate-950/95 border-amber-500/90 text-slate-100 shadow-amber-950/40'
              : toast.type === 'success'
              ? 'bg-slate-950/95 border-emerald-500/90 text-slate-100 shadow-emerald-950/40 ring-1 ring-emerald-500/30'
              : 'bg-slate-950/95 border-indigo-500/90 text-slate-100 shadow-indigo-950/40'
          }`}
        >
          {/* Animated timer bar */}
          <div
            className={`absolute bottom-0 left-0 h-1 transition-all ease-linear ${
              toast.type === 'violation'
                ? 'bg-rose-500'
                : toast.type === 'warning'
                ? 'bg-amber-500'
                : toast.type === 'success'
                ? 'bg-emerald-500'
                : 'bg-indigo-500'
            }`}
            style={{
              animation: `toastProgress ${toast.duration || 6000}ms linear forwards`
            }}
          />

          <div className="flex items-start gap-3">
            {/* Icon */}
            <div className="shrink-0 mt-0.5">
              {toast.type === 'violation' ? (
                <div className="p-2 bg-rose-950/80 border border-rose-800 rounded-lg animate-pulse">
                  <ShieldAlert className="w-5 h-5 text-rose-400" />
                </div>
              ) : toast.type === 'warning' ? (
                <div className="p-2 bg-amber-950/80 border border-amber-800 rounded-lg">
                  <AlertTriangle className="w-5 h-5 text-amber-400" />
                </div>
              ) : toast.type === 'success' ? (
                <div className="p-2 bg-emerald-950/80 border border-emerald-800 rounded-lg">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                </div>
              ) : (
                <div className="p-2 bg-indigo-950/80 border border-indigo-800 rounded-lg">
                  <Info className="w-5 h-5 text-indigo-400" />
                </div>
              )}
            </div>

            {/* Content */}
            <div className="flex-1 space-y-1 pr-4">
              <div className="flex items-center justify-between">
                <span
                  className={`text-xs font-mono font-bold uppercase tracking-wide ${
                    toast.type === 'violation'
                      ? 'text-rose-400'
                      : toast.type === 'warning'
                      ? 'text-amber-400'
                      : toast.type === 'success'
                      ? 'text-emerald-400'
                      : 'text-indigo-400'
                  }`}
                >
                  {toast.title}
                </span>
                <span className="text-[10px] font-mono text-slate-500">
                  {new Date(toast.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                </span>
              </div>

              <p className="text-xs text-slate-200 leading-relaxed font-sans font-medium">
                {toast.message}
              </p>

              {toast.filePath && (
                <div className="text-[11px] font-mono text-slate-400 truncate bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800 mt-1">
                  📄 {toast.filePath}
                </div>
              )}

              {/* Action Button */}
              {toast.onAction && (
                <div className="pt-2">
                  <button
                    onClick={() => {
                      toast.onAction?.();
                      dismissToast(toast.id);
                    }}
                    className={`text-xs font-mono font-bold px-3 py-1 rounded-md border flex items-center gap-1.5 transition-all ${
                      toast.type === 'violation'
                        ? 'bg-rose-950 text-rose-200 border-rose-800 hover:bg-rose-900'
                        : toast.type === 'success'
                        ? 'bg-emerald-950 text-emerald-200 border-emerald-800 hover:bg-emerald-900'
                        : 'bg-indigo-950 text-indigo-200 border-indigo-800 hover:bg-indigo-900'
                    }`}
                  >
                    <span>{toast.actionLabel || 'Inspect Details'}</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                </div>
              )}
            </div>

            {/* Close Button */}
            <button
              onClick={() => dismissToast(toast.id)}
              className="text-slate-500 hover:text-slate-200 p-1 rounded-lg transition-colors shrink-0"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      ))}
    </div>
  );
};

export const NotificationTrayDrawer: React.FC<{
  onNavigateToTab?: (tab: any) => void;
  onSelectFile?: (fileId: string) => void;
}> = ({ onNavigateToTab, onSelectFile }) => {
  const {
    notificationHistory,
    unreadCount,
    markAllAsRead,
    clearHistory,
    isTrayOpen,
    setIsTrayOpen
  } = useToast();

  if (!isTrayOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex justify-end animate-in fade-in-20">
      <div className="bg-slate-950 border-l border-slate-800 max-w-md w-full h-full flex flex-col shadow-2xl animate-in slide-in-from-right-10 duration-200">
        {/* Tray Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/50">
          <div className="flex items-center gap-2">
            <Bell className="w-5 h-5 text-emerald-400" />
            <h2 className="text-sm font-bold text-slate-100">Security Alert History</h2>
            {unreadCount > 0 && (
              <span className="bg-rose-600 text-white font-mono text-[10px] font-bold px-2 py-0.5 rounded-full">
                {unreadCount} UNREAD
              </span>
            )}
          </div>
          <button
            onClick={() => setIsTrayOpen(false)}
            className="text-slate-400 hover:text-white p-1 rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tray Toolbar */}
        <div className="px-4 py-2 bg-slate-900/30 border-b border-slate-800 flex items-center justify-between text-xs font-mono">
          <button
            onClick={markAllAsRead}
            disabled={unreadCount === 0}
            className="text-emerald-400 hover:text-emerald-300 disabled:opacity-40 flex items-center gap-1"
          >
            <Check className="w-3.5 h-3.5" /> Mark all read
          </button>

          <button
            onClick={clearHistory}
            disabled={notificationHistory.length === 0}
            className="text-slate-400 hover:text-rose-400 disabled:opacity-40 flex items-center gap-1 transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" /> Clear history
          </button>
        </div>

        {/* Tray Item List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3 divide-y divide-slate-800/60">
          {notificationHistory.length === 0 ? (
            <div className="p-12 text-center text-xs font-mono text-slate-500 space-y-2">
              <Bell className="w-8 h-8 text-slate-700 mx-auto" />
              <div>No notification logs stored yet.</div>
            </div>
          ) : (
            notificationHistory.map(n => (
              <div
                key={n.id}
                className={`pt-3 first:pt-0 p-3 rounded-xl border transition-all ${
                  !n.read ? 'bg-slate-900/80 border-slate-700' : 'bg-slate-950/40 border-slate-900/80 opacity-80'
                }`}
              >
                <div className="flex items-start gap-2.5">
                  {n.type === 'violation' ? (
                    <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  ) : n.type === 'warning' ? (
                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  ) : n.type === 'success' ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  ) : (
                    <Info className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
                  )}

                  <div className="flex-1 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className={`text-xs font-mono font-bold ${
                        n.type === 'violation' ? 'text-rose-400' : n.type === 'success' ? 'text-emerald-400' : 'text-slate-200'
                      }`}>
                        {n.title}
                      </span>
                      <span className="text-[10px] font-mono text-slate-500">
                        {new Date(n.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>

                    <p className="text-xs text-slate-300 font-sans leading-relaxed">
                      {n.message}
                    </p>

                    {n.fileId && onSelectFile && (
                      <button
                        onClick={() => {
                          onSelectFile(n.fileId!);
                          setIsTrayOpen(false);
                        }}
                        className="text-[11px] font-mono text-emerald-400 hover:underline block pt-1"
                      >
                        → Inspect File in Detail View
                      </button>
                    )}

                    {n.scanId && onNavigateToTab && (
                      <button
                        onClick={() => {
                          onNavigateToTab('audit');
                          setIsTrayOpen(false);
                        }}
                        className="text-[11px] font-mono text-indigo-400 hover:underline block pt-1"
                      >
                        → Open Audit Report
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
