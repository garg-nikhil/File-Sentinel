import React, { useState, useEffect } from 'react';
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
  FileCheck,
  KeyRound,
  Cloud,
  Fingerprint,
  ShieldCheck,
  Laptop,
  Bell
} from 'lucide-react';
import { api } from '../services/api';
import { LicenseInfo } from '../types';
import { useToast } from '../context/ToastContext';

export type NavTab =
  | 'dashboard'
  | 'cloud_dashboard'
  | 'endpoint_compliance'
  | 'audit'
  | 'verify_report'
  | 'scan'
  | 'files'
  | 'findings'
  | 'quarantine'
  | 'rules'
  | 'history'
  | 'license'
  | 'settings'
  | 'admin_console';

interface SidebarProps {
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
  isScanning?: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, setActiveTab, isScanning }) => {
  const [license, setLicense] = useState<LicenseInfo | null>(null);
  const { unreadCount, setIsTrayOpen } = useToast();

  useEffect(() => {
    api.getLicense().then(setLicense).catch(() => {});
  }, [activeTab]);

  const menuItems: { id: NavTab; label: string; icon: React.ReactNode }[] = [
    { id: 'dashboard', label: 'Local DLP Overview', icon: <LayoutDashboard className="w-4 h-4" /> },
    { id: 'cloud_dashboard', label: 'Vendor Cloud Dashboard', icon: <Cloud className="w-4 h-4 text-emerald-400" /> },
    { id: 'endpoint_compliance', label: 'Endpoint Compliance', icon: <Laptop className="w-4 h-4 text-cyan-400" /> },
    { id: 'audit', label: 'Audit Compliance', icon: <FileCheck className="w-4 h-4" /> },
    { id: 'verify_report', label: 'Report Verification', icon: <Fingerprint className="w-4 h-4 text-indigo-400" /> },
    { id: 'scan', label: 'Scanner', icon: <FolderSearch className="w-4 h-4" /> },
    { id: 'files', label: 'Scanned Files', icon: <FileText className="w-4 h-4" /> },
    { id: 'findings', label: 'Findings Log', icon: <AlertTriangle className="w-4 h-4" /> },
    { id: 'quarantine', label: 'Quarantine Vault', icon: <ShieldAlert className="w-4 h-4" /> },
    { id: 'rules', label: 'Rule Engine', icon: <SlidersHorizontal className="w-4 h-4" /> },
    { id: 'history', label: 'Scan History', icon: <History className="w-4 h-4" /> },
    { id: 'license', label: 'License & Plan', icon: <KeyRound className="w-4 h-4" /> },
    { id: 'admin_console', label: 'Admin Console', icon: <ShieldCheck className="w-4 h-4 text-rose-400" /> },
    { id: 'settings', label: 'Settings', icon: <Settings className="w-4 h-4" /> }
  ];

  return (
    <aside id="app-sidebar" className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between select-none">
      <div>
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-base font-bold text-slate-100 tracking-tight flex items-center gap-2">
                FileSentinel
                <span className="text-[10px] font-mono font-normal uppercase bg-emerald-500/20 text-emerald-300 px-1.5 py-0.5 rounded border border-emerald-500/30">
                  PRO
                </span>
              </h1>
              <p className="text-xs text-slate-400 font-sans">Local DLP & Compliance</p>
            </div>
          </div>

          <button
            onClick={() => setIsTrayOpen(true)}
            title="Security Alert History"
            className="relative p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors border border-slate-700"
          >
            <Bell className="w-4 h-4 text-emerald-400" />
            {unreadCount > 0 && (
              <span className="absolute -top-1.5 -right-1.5 bg-rose-600 text-white font-mono text-[9px] font-bold w-4 h-4 rounded-full flex items-center justify-center border border-slate-900 animate-pulse">
                {unreadCount > 9 ? '9+' : unreadCount}
              </span>
            )}
          </button>
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
                {item.id === 'license' && license && (
                  <span className={`ml-auto text-[10px] font-mono px-1.5 py-0.5 rounded ${
                    license.ui_state === 'ACTIVE'
                      ? 'bg-emerald-500/20 text-emerald-300'
                      : license.ui_state === 'TRIAL'
                      ? 'bg-blue-500/20 text-blue-300'
                      : license.ui_state === 'OFFLINE_GRACE'
                      ? 'bg-amber-500/20 text-amber-300 animate-pulse'
                      : 'bg-rose-500/20 text-rose-300'
                  }`}>
                    {license.ui_state}
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
          <span>License Plan:</span>
          <span className="text-slate-300 font-mono font-semibold">
            {license?.plan_name || 'Enterprise'}
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
