import React, { useState, useEffect } from 'react';
import { Sidebar, NavTab } from './components/Sidebar';
import { DashboardView } from './components/DashboardView';
import { ScanView } from './components/ScanView';
import { FilesView } from './components/FilesView';
import { FileDetailView } from './components/FileDetailView';
import { FindingsView } from './components/FindingsView';
import { QuarantineView } from './components/QuarantineView';
import { RulesView } from './components/RulesView';
import { HistoryView } from './components/HistoryView';
import { SettingsView } from './components/SettingsView';
import { LicenseView } from './components/LicenseView';
import { AuditComplianceView } from './components/audit/AuditComplianceView';
import { VendorCloudDashboardView } from './components/VendorCloudDashboardView';
import { EndpointComplianceView } from './components/EndpointComplianceView';
import { ReportVerificationView } from './components/ReportVerificationView';
import { AdminConsoleView } from './components/AdminConsoleView';
import { api } from './services/api';
import { ClientClockMonitor } from './services/clockMonitor';
import { AlertTriangle, RefreshCw, Download } from 'lucide-react';
import { DashboardStats, ScanSession } from './types';
import { ToastProvider } from './context/ToastContext';
import { ToastContainer, NotificationTrayDrawer } from './components/ToastContainer';

function MainLayout() {
  const [activeTab, setActiveTab] = useState<NavTab>('dashboard');
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [activeScan, setActiveScan] = useState<ScanSession | null>(null);
  const [recentScanId, setRecentScanId] = useState<string | null>(null);
  const [theme, setTheme] = useState<string>('midnight-emerald');
  const [isScanLocked, setIsScanLocked] = useState<boolean>(false);
  const [lockReason, setLockReason] = useState<string>('');
  const [isRevalidating, setIsRevalidating] = useState<boolean>(false);
  const [revalidateError, setRevalidateError] = useState<string | null>(null);
  const [isDownloadingLogs, setIsDownloadingLogs] = useState<boolean>(false);
  const [autoRevalidate, setAutoRevalidate] = useState<boolean>(false);

  // Auto-attempt revalidation every 60s if enabled
  useEffect(() => {
    if (!isScanLocked || !autoRevalidate) return;

    const interval = setInterval(() => {
      console.log('[Auto-Revalidate] Periodically attempting revalidation...');
      handleRevalidate();
    }, 60000);

    return () => clearInterval(interval);
  }, [isScanLocked, autoRevalidate]);

  const handleDownloadLogs = async () => {
    setIsDownloadingLogs(true);
    setRevalidateError(null);
    try {
      const logs = await api.getClockMonitorLogs();
      if (logs && logs.length > 0) {
        const headers = ['Log ID', 'Timestamp', 'Drift (ms)', 'Performance Time (ms)', 'Date Time (ms)', 'Status'];
        const csvRows = [headers.join(',')];
        
        for (const log of logs) {
          const row = [
            log.id,
            log.timestamp,
            log.delta_ms,
            log.elapsed_performance_ms,
            log.elapsed_date_ms,
            log.status
          ];
          csvRows.push(row.map(val => `"${val}"`).join(','));
        }
        
        const csvContent = csvRows.join('\n');
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.setAttribute('href', url);
        link.setAttribute('download', `forensic_clock_drift_logs_${new Date().toISOString().slice(0, 10)}.csv`);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
      } else {
        setRevalidateError('No forensic heartbeat logs found in database. Check back once some checks occur.');
      }
    } catch (err: any) {
      setRevalidateError(`Failed to export forensic logs: ${err.message}`);
    } finally {
      setIsDownloadingLogs(false);
    }
  };

  const handleRevalidate = async () => {
    setIsRevalidating(true);
    setRevalidateError(null);
    try {
      const response = await api.revalidateOfflineLicense();
      if (response.success && response.valid) {
        setIsScanLocked(false);
        setLockReason('');
        localStorage.setItem('last_successful_sync', new Date().toISOString());
        loadStats();
      } else {
        setRevalidateError(response.error || 'Revalidation failed. Keep clock synchronized.');
      }
    } catch (err: any) {
      setRevalidateError(err.message || 'System clock is still out of sync.');
    } finally {
      setIsRevalidating(false);
    }
  };

  useEffect(() => {
    // 1. Initial server-side clock block check
    const checkServerLicense = async () => {
      try {
        const status = await api.getOfflineLicenseStatus();
        if (status && (status.status === 'CLOCK_ROLLBACK_DETECTED' || status.clockRollbackDetected)) {
          setIsScanLocked(true);
          setLockReason('System clock tampering or rollback detected on backend. Scanning is blocked.');
        } else {
          localStorage.setItem('last_successful_sync', new Date().toISOString());
        }
      } catch (e) {
        console.error('License check error:', e);
      }
    };
    checkServerLicense();

    // 2. Client-side interval observer
    const monitor = new ClientClockMonitor();
    monitor.start((reason) => {
      setIsScanLocked(true);
      setLockReason(reason);
    });

    return () => {
      monitor.stop();
    };
  }, []);

  useEffect(() => {
    loadStats();
    loadTheme();
  }, [activeTab]);

  const loadStats = async () => {
    try {
      const data = await api.getDashboardStats();
      setStats(data);
    } catch (e) {
      console.error(e);
    }
  };

  const loadTheme = async () => {
    try {
      const settings = await api.getSettings();
      if (settings && settings.theme) {
        setTheme(settings.theme);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleSelectFile = (fileId: string) => {
    setSelectedFileId(fileId);
  };

  const handleStartQuickScan = () => {
    setActiveTab('scan');
  };

  const handleScanComplete = (scanId: string) => {
    loadStats();
    loadTheme();
    setRecentScanId(scanId);
    setActiveTab('audit');
  };

  const getThemeWrapperClass = () => {
    switch (theme) {
      case 'cyber-neon':
        return 'flex h-screen bg-zinc-950 text-zinc-100 font-sans antialiased overflow-hidden selection:bg-cyan-500/30 selection:text-cyan-200';
      case 'warm-executive':
        return 'flex h-screen bg-stone-950 text-stone-100 font-sans antialiased overflow-hidden selection:bg-amber-500/30 selection:text-amber-200';
      case 'clean-light':
        return 'flex h-screen bg-slate-100 text-slate-900 font-sans antialiased overflow-hidden selection:bg-emerald-500/20 selection:text-emerald-800';
      case 'midnight-emerald':
      default:
        return 'flex h-screen bg-slate-950 text-slate-100 font-sans antialiased overflow-hidden selection:bg-emerald-500/30 selection:text-emerald-200';
    }
  };

  return (
    <div className={getThemeWrapperClass()}>
      {/* Sidebar Navigation */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={tab => {
          setSelectedFileId(null);
          setActiveTab(tab);
          if (tab !== 'audit') {
            setRecentScanId(null);
          }
          loadTheme();
        }}
        isScanning={activeScan?.status === 'SCANNING'}
      />

      {/* Main Content Workspace */}
      <main className={`flex-1 overflow-y-auto ${theme === 'clean-light' ? 'bg-slate-50' : theme === 'cyber-neon' ? 'bg-zinc-950' : theme === 'warm-executive' ? 'bg-stone-950' : 'bg-slate-950'}`}>
        {isScanLocked && (
          <div className="bg-red-500/10 border-b border-red-500/20 px-6 py-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 text-red-200">
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="px-2 py-0.5 bg-red-500/20 rounded text-red-400 font-bold font-mono text-xs uppercase tracking-wider">Scan Locked</span>
                  <p className="text-sm font-medium">{lockReason || 'System clock tampering or rollback detected. Scanning is blocked until revalidation.'}</p>
                </div>
                {(() => {
                  const lastSync = localStorage.getItem('last_successful_sync');
                  return (
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-1 text-xs text-slate-400 font-mono">
                      {lastSync && (
                        <span>
                          Last Successful Sync: <span className="text-slate-300 font-semibold">{new Date(lastSync).toLocaleString()}</span>
                        </span>
                      )}
                      <span className="flex items-center gap-1.5 text-emerald-400 font-semibold">
                        <span className="relative flex h-1.5 w-1.5">
                          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                          <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
                        </span>
                        Background Heartbeat Active
                      </span>
                    </div>
                  );
                })()}
                <div className="flex items-center gap-2 mt-2 select-none">
                  <label className="inline-flex items-center gap-2 text-xs text-red-300 font-mono cursor-pointer">
                    <input
                      id="chk-auto-revalidate"
                      type="checkbox"
                      checked={autoRevalidate}
                      onChange={(e) => setAutoRevalidate(e.target.checked)}
                      className="w-3.5 h-3.5 rounded border-red-500/30 text-red-600 bg-red-950/40 focus:ring-red-500 focus:ring-offset-red-950 cursor-pointer"
                    />
                    <span>Auto-Attempt Revalidation (every 60s)</span>
                  </label>
                </div>
                {revalidateError && (
                  <p className="text-xs text-red-400 mt-1.5 font-mono bg-red-950/40 px-2 py-1 rounded border border-red-500/10 max-w-xl">
                    <span className="font-bold">Error:</span> {revalidateError}
                  </p>
                )}
              </div>
            </div>
            <div className="flex items-center gap-3 shrink-0 self-end sm:self-center">
              <button
                id="btn-download-logs"
                onClick={handleDownloadLogs}
                disabled={isDownloadingLogs}
                className="bg-slate-800 hover:bg-slate-700 active:bg-slate-900 disabled:opacity-50 text-slate-200 font-medium text-xs px-4 py-2 rounded-lg flex items-center gap-2 transition-all shadow-sm border border-slate-700 cursor-pointer"
              >
                <Download className={`w-3.5 h-3.5 ${isDownloadingLogs ? 'animate-pulse' : ''}`} />
                {isDownloadingLogs ? 'Exporting...' : 'Download Logs'}
              </button>
              <button
                id="btn-license-revalidate"
                onClick={handleRevalidate}
                disabled={isRevalidating}
                className="bg-red-600 hover:bg-red-500 active:bg-red-700 disabled:opacity-50 text-white font-medium text-xs px-4 py-2 rounded-lg flex items-center gap-2 transition-all shadow-sm border border-red-500/30 cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isRevalidating ? 'animate-spin' : ''}`} />
                {isRevalidating ? 'Revalidating Clock...' : 'Revalidate License'}
              </button>
              <div className="text-xs font-mono px-2.5 py-1 bg-red-500/20 border border-red-500/30 rounded text-red-300">
                REVALIDATE REQUIRED
              </div>
            </div>
          </div>
        )}

        {selectedFileId ? (
          <FileDetailView
            fileId={selectedFileId}
            onBack={() => setSelectedFileId(null)}
          />
        ) : (
          <>
            {activeTab === 'dashboard' && (
              <DashboardView
                stats={stats}
                onNavigate={setActiveTab}
                onSelectFile={handleSelectFile}
                onStartQuickScan={handleStartQuickScan}
              />
            )}

            {activeTab === 'cloud_dashboard' && (
              <VendorCloudDashboardView />
            )}

            {activeTab === 'endpoint_compliance' && (
              <EndpointComplianceView />
            )}

            {activeTab === 'audit' && (
              <div className="p-6">
                <AuditComplianceView recentScanId={recentScanId} />
              </div>
            )}

            {activeTab === 'verify_report' && (
              <ReportVerificationView />
            )}

            {activeTab === 'scan' && (
              <ScanView
                onScanComplete={handleScanComplete}
                activeScan={activeScan}
                setActiveScan={setActiveScan}
                isScanLocked={isScanLocked}
              />
            )}

            {activeTab === 'files' && (
              <FilesView onSelectFile={handleSelectFile} />
            )}

            {activeTab === 'findings' && <FindingsView />}

            {activeTab === 'quarantine' && <QuarantineView />}

            {activeTab === 'rules' && <RulesView />}

            {activeTab === 'history' && <HistoryView />}

            {activeTab === 'license' && <LicenseView />}

            {activeTab === 'admin_console' && <AdminConsoleView />}

            {activeTab === 'settings' && <SettingsView />}
          </>
        )}
      </main>

      {/* Real-time Toast Overlay & Notification History Drawer */}
      <ToastContainer />
      <NotificationTrayDrawer
        onNavigateToTab={setActiveTab}
        onSelectFile={handleSelectFile}
      />
    </div>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <MainLayout />
    </ToastProvider>
  );
}
