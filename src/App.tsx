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
import { ReportVerificationView } from './components/ReportVerificationView';
import { AdminConsoleView } from './components/AdminConsoleView';
import { api } from './services/api';
import { DashboardStats, ScanSession } from './types';

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('dashboard');
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [activeScan, setActiveScan] = useState<ScanSession | null>(null);
  const [recentScanId, setRecentScanId] = useState<string | null>(null);
  const [theme, setTheme] = useState<string>('midnight-emerald');

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
    </div>
  );
}
