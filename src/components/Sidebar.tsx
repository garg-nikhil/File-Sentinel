import React from 'react';
import {
  LayoutDashboard,
  FolderSearch,
  FileText,
  AlertTriangle,
  ShieldAlert,
  SlidersHorizontal,
  History,
  Settings,
  Shield,
  Radio,
  FileCheck
} from 'lucide-react';

export type NavTab =
  | 'dashboard'
  | 'audit'
  | 'scan'
  | 'files'
  | 'findings'
  | 'quarantine'
  | 'rules'
  | 'history'
  | 'settings';

interface SidebarProps {
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
  isScanning?: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, setActiveTab, isScanning }) => {
  const menuItems: { id: NavTab; label: string; icon: React.ReactNode }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard className="w-4 h-4" /> },
    { id: 'audit', label: 'Audit Compliance', icon: <FileCheck className="w-4 h-4" /> },
    { id: 'scan', label: 'Scanner', icon: <FolderSearch className="w-4 h-4" /> },
    { id: 'files', label: 'Scanned Files', icon: <FileText className="w-4 h-4" /> },
    { id: 'findings', label: 'Findings Log', icon: <AlertTriangle className="w-4 h-4" /> },
    { id: 'quarantine', label: 'Quarantine Vault', icon: <ShieldAlert className="w-4 h-4" /> },
    { id: 'rules', label: 'Rule Engine', icon: <SlidersHorizontal className="w-4 h-4" /> },
    { id: 'history', label: 'Scan History', icon: <History className="w-4 h-4" /> },
    { id: 'settings', label: 'Settings', icon: <Settings className="w-4 h-4" /> }
  ];

  return (
    <aside id="app-sidebar" className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between select-none">
      <div>
        <div className="p-5 border-b border-slate-800 flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-bold text-slate-100 tracking-tight flex items-center gap-2">
              FileSentinel
              <span className="text-[10px] font-mono font-normal uppercase bg-emerald-500/20 text-emerald-300 px-1.5 py-0.5 rounded border border-emerald-500/30">
                MVP
              </span>
            </h1>
            <p className="text-xs text-slate-400 font-sans">Local DLP & Compliance</p>
          </div>
        </div>

        <nav className="p-3 space-y-1">
          {menuItems.map(item => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                id={`nav-item-${item.id}`}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <span className={isActive ? 'text-emerald-400' : 'text-slate-500'}>{item.icon}</span>
                {item.label}
                {item.id === 'scan' && isScanning && (
                  <span className="ml-auto flex items-center text-amber-400 text-xs animate-pulse">
                    <Radio className="w-3.5 h-3.5 mr-1" />
                    Scanning
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      <div className="p-4 border-t border-slate-800/80 bg-slate-950/40 text-xs text-slate-400 space-y-2">
        <div className="flex items-center justify-between text-slate-400">
          <span>Engine Status:</span>
          <span className="text-emerald-400 font-mono font-medium flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            ACTIVE
          </span>
        </div>
        <div className="flex items-center justify-between text-slate-400">
          <span>Storage Vault:</span>
          <span className="text-slate-300 font-mono">SQLite (Local)</span>
        </div>
      </div>
    </aside>
  );
};
