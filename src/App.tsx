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
import { AuditComplianceView } from './components/audit/AuditComplianceView';
import { api } from './services/api';
import { DashboardStats, ScanSession } from './types';

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('dashboard');
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [activeScan, setActiveScan] = useState<ScanSession | null>(null);
  const [recentScanId, setRecentScanId] = useState<string | null>(null);

  useEffect(() => {
    loadStats();
  }, [activeTab]);

  const loadStats = async () => {
    try {
      const data = await api.getDashboardStats();
      setStats(data);
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
    setRecentScanId(scanId);
    setActiveTab('audit');
  };

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 font-sans antialiased overflow-hidden selection:bg-emerald-500/30 selection:text-emerald-200">
      {/* Sidebar Navigation */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={tab => {
          setSelectedFileId(null);
          setActiveTab(tab);
          if (tab !== 'audit') {
            setRecentScanId(null);
          }
        }}
        isScanning={activeScan?.status === 'SCANNING'}
      />

      {/* Main Content Workspace */}
      <main className="flex-1 overflow-y-auto bg-slate-950">
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

            {activeTab === 'audit' && (
              <div className="p-6">
                <AuditComplianceView recentScanId={recentScanId} />
              </div>
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

            {activeTab === 'settings' && <SettingsView />}
          </>
        )}
      </main>
    </div>
  );
}
