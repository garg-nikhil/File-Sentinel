import React, { useState, useEffect } from 'react';
import {
  KeyRound,
  ShieldCheck,
  ShieldAlert,
  Clock,
  Laptop,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Cpu,
  Layers,
  FileCheck,
  History,
  Lock,
  ChevronRight
} from 'lucide-react';
import { api } from '../services/api';
import { LicenseInfo, LicenseDevice, LicenseAuditEvent } from '../types';

export const LicenseView: React.FC = () => {
  const [license, setLicense] = useState<LicenseInfo | null>(null);
  const [devices, setDevices] = useState<LicenseDevice[]>([]);
  const [events, setEvents] = useState<LicenseAuditEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [actionMsg, setActionMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const fetchLicenseData = async () => {
    try {
      setLoading(true);
      const licData = await api.getLicense();
      setLicense(licData);
      
      const [devData, evData] = await Promise.all([
        api.getLicenseDevices().catch(() => []),
        api.getLicenseEvents().catch(() => [])
      ]);
      setDevices(devData || []);
      setEvents(evData || []);
    } catch (err: any) {
      console.error('Failed to load licensing info:', err);
      setActionMsg({ type: 'error', text: err.message || 'Unable to connect to license validation server' });
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchLicenseData();
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchLicenseData();
  };

  const handleDeactivate = async (deviceId: string) => {
    try {
      const res = await api.deactivateLicenseDevice(deviceId);
      if (res.success) {
        setActionMsg({ type: 'success', text: `Device ${deviceId} deactivated successfully.` });
        fetchLicenseData();
      } else {
        setActionMsg({ type: 'error', text: res.error || 'Failed to deactivate device.' });
      }
    } catch (e: any) {
      setActionMsg({ type: 'error', text: e.message || 'Error executing deactivation request.' });
    }
  };

  const getStatusBadge = (uiState?: string, status?: string) => {
    switch (uiState || status) {
      case 'ACTIVE':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3.5 h-3.5" /> License Active
          </span>
        );
      case 'TRIAL':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/30">
            <Clock className="w-3.5 h-3.5" /> Trial Evaluation
          </span>
        );
      case 'EXPIRING_SOON':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3.5 h-3.5" /> Expiring Soon
          </span>
        );
      case 'OFFLINE_GRACE':
      case 'GRACE_PERIOD':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse">
            <Clock className="w-3.5 h-3.5" /> Offline Grace Period
          </span>
        );
      case 'DEVICE_LIMIT_REACHED':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-orange-500/10 text-orange-400 border border-orange-500/30">
            <Laptop className="w-3.5 h-3.5" /> Device Limit Reached
          </span>
        );
      case 'SCAN_LIMIT_REACHED':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-orange-500/10 text-orange-400 border border-orange-500/30">
            <AlertTriangle className="w-3.5 h-3.5" /> Scan Limit Reached
          </span>
        );
      case 'EXPIRED':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <XCircle className="w-3.5 h-3.5" /> License Expired
          </span>
        );
      case 'SUSPENDED':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/40">
            <Lock className="w-3.5 h-3.5" /> Suspended
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
            {status || 'Unknown'}
          </span>
        );
    }
  };

  const featureList = [
    { key: 'LOCAL_SCANNING', name: 'Deterministic Local Scanning', desc: 'Full deep multi-format document DLP extraction and rule evaluation' },
    { key: 'AUDIT_ENGINE', name: 'Compliance Evidence Engine', desc: 'Automated checklist verification, entity resolution, and audit scoring' },
    { key: 'MULTI_FOLDER_SCAN', name: 'Multi-Directory Batch Scanning', desc: 'Scan multiple disconnected workspaces concurrently' },
    { key: 'CLOUD_EVIDENCE_UPLOAD', name: 'Cloud Vault Upload & Verification', desc: 'Encrypted object storage upload with SHA-256 verification' },
    { key: 'CENTRAL_HISTORY', name: 'Central Audit Persistence', desc: 'Structured SQLite local compliance records and audit history' },
    { key: 'ADVANCED_REPORTING', name: 'Advanced Audit Inventory Reports', desc: 'Export certified evidence inventory and compliance audit packets' },
    { key: 'API_ACCESS', name: 'Headless Agent / API Integration', desc: 'Automated CI/CD and CLI agent telemetry orchestration' }
  ];

  if (loading) {
    return (
      <div className="p-8 flex flex-col items-center justify-center min-h-[400px] text-slate-400">
        <RefreshCw className="w-8 h-8 animate-spin text-emerald-500 mb-3" />
        <p className="text-sm font-medium">Validating FileSentinel license with server...</p>
      </div>
    );
  }

  return (
    <div id="license-management-view" className="p-8 max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
            <KeyRound className="w-7 h-7 text-emerald-400" />
            License & Subscription
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Server-authoritative entitlements, device allocation, and subscription status
          </p>
        </div>
        <button
          id="refresh-license-btn"
          onClick={handleRefresh}
          disabled={refreshing}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium transition border border-slate-700 disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin text-emerald-400' : ''}`} />
          Revalidate License
        </button>
      </div>

      {actionMsg && (
        <div
          className={`p-4 rounded-lg flex items-center justify-between text-sm ${
            actionMsg.type === 'success'
              ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border border-rose-500/30 text-rose-300'
          }`}
        >
          <span>{actionMsg.text}</span>
          <button onClick={() => setActionMsg(null)} className="text-slate-400 hover:text-slate-200 font-bold ml-4">
            ✕
          </button>
        </div>
      )}

      {/* Primary License Overview Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              {getStatusBadge(license?.ui_state, license?.status)}
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wide">
                Plan: <strong className="text-slate-200">{license?.plan_name || 'Enterprise'}</strong>
              </span>
            </div>
            <h3 className="text-xl font-bold text-slate-100">
              Organization: <span className="text-emerald-400 font-mono">{license?.organization_id || 'org-default-dev'}</span>
            </h3>
            <p className="text-xs font-mono text-slate-400">
              License ID: <span className="text-slate-300">{license?.license_id || 'N/A'}</span>
            </p>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 border-t lg:border-t-0 lg:border-l border-slate-800 lg:pl-6 pt-4 lg:pt-0">
            <div>
              <div className="text-xs text-slate-400">Days Remaining</div>
              <div className="text-lg font-bold text-slate-100 mt-0.5">
                {license?.days_remaining != null ? `${license.days_remaining} days` : 'Unlimited'}
              </div>
            </div>
            <div>
              <div className="text-xs text-slate-400">Expires At</div>
              <div className="text-sm font-medium text-slate-300 mt-0.5">
                {license?.expires_at ? new Date(license.expires_at).toLocaleDateString() : 'N/A'}
              </div>
            </div>
            <div>
              <div className="text-xs text-slate-400">Grace Until</div>
              <div className="text-sm font-medium text-amber-400 mt-0.5">
                {license?.grace_until ? new Date(license.grace_until).toLocaleDateString() : 'N/A'}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Quotas & Capacity */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Device Quota */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <Laptop className="w-4 h-4 text-emerald-400" /> Device Allocation
            </span>
            <span className="text-xs font-mono text-emerald-400 font-semibold">
              {devices.filter(d => d.status === 'ACTIVE').length} / {license?.max_devices || 1}
            </span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div
              className="bg-emerald-500 h-full rounded-full transition-all"
              style={{
                width: `${Math.min(
                  100,
                  ((devices.filter(d => d.status === 'ACTIVE').length || 1) / (license?.max_devices || 1)) * 100
                )}%`
              }}
            />
          </div>
          <p className="text-xs text-slate-400">
            Registered and active Windows workstations bound to this license.
          </p>
        </div>

        {/* Scan Quota */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <Layers className="w-4 h-4 text-emerald-400" /> Monthly Scan Quota
            </span>
            <span className="text-xs font-mono text-emerald-400 font-semibold">
              {license?.scan_limit === -1 ? 'Unlimited' : `${license?.scans_used || 0} / ${license?.scan_limit}`}
            </span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div
              className="bg-emerald-500 h-full rounded-full transition-all"
              style={{
                width:
                  license?.scan_limit === -1
                    ? '10%'
                    : `${Math.min(100, ((license?.scans_used || 0) / (license?.scan_limit || 1)) * 100)}%`
              }}
            />
          </div>
          <p className="text-xs text-slate-400">
            {license?.scan_limit === -1
              ? 'Unlimited scanning included in your active plan.'
              : `${(license?.scan_limit || 0) - (license?.scans_used || 0)} scans remaining in current billing cycle.`}
          </p>
        </div>

        {/* User Seats */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <Cpu className="w-4 h-4 text-emerald-400" /> Auditor & Operator Seats
            </span>
            <span className="text-xs font-mono text-emerald-400 font-semibold">
              Max {license?.max_users || 10} Users
            </span>
          </div>
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
            <div className="bg-emerald-500 h-full rounded-full w-1/4" />
          </div>
          <p className="text-xs text-slate-400">
            Role-based team seats allocated for ORG_ADMIN, AUDITOR, and OPERATOR users.
          </p>
        </div>
      </div>

      {/* Feature Entitlements */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
          Feature Entitlements & Plan Inclusions
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {featureList.map(feat => {
            const isEnabled = license?.feature_flags?.includes(feat.key);
            return (
              <div
                key={feat.key}
                className={`p-3.5 rounded-lg border flex items-start gap-3 transition ${
                  isEnabled
                    ? 'bg-slate-950/60 border-slate-800 text-slate-200'
                    : 'bg-slate-950/30 border-slate-800/40 text-slate-500 opacity-60'
                }`}
              >
                {isEnabled ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                ) : (
                  <XCircle className="w-5 h-5 text-slate-600 shrink-0 mt-0.5" />
                )}
                <div>
                  <div className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                    {feat.name}
                    {isEnabled ? (
                      <span className="text-[10px] bg-emerald-500/10 text-emerald-400 px-1.5 py-0.5 rounded font-mono">
                        ENABLED
                      </span>
                    ) : (
                      <span className="text-[10px] bg-slate-800 text-slate-400 px-1.5 py-0.5 rounded font-mono">
                        LOCKED
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">{feat.desc}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Device Management */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Laptop className="w-5 h-5 text-emerald-400" />
              Activated Workstations & Devices
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Authorized endpoints permitted to execute local DLP and compliance scans
            </p>
          </div>
          <span className="text-xs font-mono bg-slate-800 px-2.5 py-1 rounded text-slate-300">
            {devices.filter(d => d.status === 'ACTIVE').length} of {license?.max_devices} slots used
          </span>
        </div>

        {devices.length === 0 ? (
          <div className="p-8 text-center text-slate-500 border border-dashed border-slate-800 rounded-lg text-sm">
            No devices currently registered for this license.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-950/60 text-xs uppercase font-mono text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="p-3">Device Name & ID</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Activated At</th>
                  <th className="p-3">Last Seen</th>
                  <th className="p-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {devices.map(dev => (
                  <tr key={dev.id} className="hover:bg-slate-800/40">
                    <td className="p-3 font-medium text-slate-100">
                      <div>{dev.device_name || 'Windows Endpoint'}</div>
                      <div className="text-xs font-mono text-slate-400">{dev.device_id}</div>
                    </td>
                    <td className="p-3">
                      {dev.status === 'ACTIVE' ? (
                        <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                          Active
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs font-medium text-slate-400 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
                          Deactivated
                        </span>
                      )}
                    </td>
                    <td className="p-3 text-xs text-slate-400">
                      {new Date(dev.activated_at).toLocaleString()}
                    </td>
                    <td className="p-3 text-xs text-slate-400">
                      {new Date(dev.last_seen_at).toLocaleString()}
                    </td>
                    <td className="p-3 text-right">
                      {dev.status === 'ACTIVE' ? (
                        <button
                          onClick={() => handleDeactivate(dev.device_id)}
                          className="px-2.5 py-1 text-xs font-medium bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 rounded transition"
                        >
                          Deactivate
                        </button>
                      ) : (
                        <span className="text-xs text-slate-500">Deactivated</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* License Audit Log */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
          <History className="w-5 h-5 text-emerald-400" />
          License Lifecycle Events
        </h3>
        {events.length === 0 ? (
          <div className="p-6 text-center text-slate-500 border border-dashed border-slate-800 rounded-lg text-sm">
            No license lifecycle audit events recorded yet.
          </div>
        ) : (
          <div className="space-y-2">
            {events.slice(0, 10).map(ev => (
              <div
                key={ev.id}
                className="p-3 rounded-lg bg-slate-950/40 border border-slate-800/80 flex items-center justify-between text-xs"
              >
                <div className="flex items-center gap-3">
                  <span className="font-mono font-semibold text-emerald-400">{ev.event_type}</span>
                  {ev.details && (
                    <span className="text-slate-400 font-mono">
                      {JSON.stringify(ev.details)}
                    </span>
                  )}
                </div>
                <div className="text-slate-400 font-mono">
                  {new Date(ev.timestamp).toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
