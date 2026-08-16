import React, { useState, useEffect } from 'react';
import {
  Cloud,
  Shield,
  TrendingUp,
  History,
  Monitor,
  Users,
  Building,
  Lock,
  Cpu,
  FileCheck2,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  HelpCircle,
  RefreshCw,
  Search,
  UserPlus,
  Trash2,
  Power,
  ShieldAlert,
  ArrowUpRight,
  ArrowDownRight,
  Clock,
  Layers,
  ChevronRight,
  CreditCard,
  Zap,
  Calendar,
  AlertCircle
} from 'lucide-react';
import { api } from '../services/api';
import {
  CloudDashboardOverview,
  ComplianceTrendPoint,
  ScanTelemetryRecord,
  CloudManagedDevice,
  CloudManagedUser,
  CloudOrgInfo,
  CloudSoftwareVersion,
  ReportVerificationResult,
  AppSettings,
  OrganizationBillingState
} from '../types';

export const VendorCloudDashboardView: React.FC = () => {
  const [activeSection, setActiveSection] = useState<
    | 'overview'
    | 'scans'
    | 'trend'
    | 'devices'
    | 'users'
    | 'organization'
    | 'billing'
    | 'privacy'
    | 'version'
    | 'verification'
  >('overview');

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Section data states
  const [overview, setOverview] = useState<CloudDashboardOverview | null>(null);
  const [scans, setScans] = useState<ScanTelemetryRecord[]>([]);
  const [selectedScanDetail, setSelectedScanDetail] = useState<ScanTelemetryRecord | null>(null);
  const [trend, setTrend] = useState<ComplianceTrendPoint[]>([]);
  const [devices, setDevices] = useState<CloudManagedDevice[]>([]);
  const [users, setUsers] = useState<CloudManagedUser[]>([]);
  const [orgInfo, setOrgInfo] = useState<CloudOrgInfo | null>(null);
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [versionInfo, setVersionInfo] = useState<CloudSoftwareVersion | null>(null);
  const [billingState, setBillingState] = useState<OrganizationBillingState | null>(null);
  const [billingActionMsg, setBillingActionMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [selectedInterval, setSelectedInterval] = useState<'MONTHLY' | 'ANNUAL'>('MONTHLY');

  // User management form state
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState<'ORG_ADMIN' | 'AUDITOR' | 'OPERATOR' | 'VIEWER'>('OPERATOR');
  const [userActionMsg, setUserActionMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Report verification state
  const [verifyQueryId, setVerifyQueryId] = useState('');
  const [verifyLoading, setVerifyLoading] = useState(false);
  const [verificationResult, setVerificationResult] = useState<ReportVerificationResult | null>(null);

  const loadAllData = async () => {
    try {
      setRefreshing(true);
      const [
        ov,
        sc,
        tr,
        dev,
        usr,
        org,
        st,
        ver,
        bill
      ] = await Promise.all([
        api.getCloudDashboardOverview().catch(() => null),
        api.getScanTelemetryHistory(50, 0).catch(() => []),
        api.getCloudComplianceTrend(30).catch(() => []),
        api.getCloudDevices().catch(() => []),
        api.getCloudUsers().catch(() => []),
        api.getCloudOrganizationInfo().catch(() => null),
        api.getSettings().catch(() => null),
        api.getCloudSoftwareVersion().catch(() => null),
        api.getBillingState().catch(() => null)
      ]);

      setOverview(ov);
      setScans(Array.isArray(sc) ? sc : []);
      setTrend(Array.isArray(tr) ? tr : []);
      setDevices(Array.isArray(dev) ? dev : []);
      setUsers(Array.isArray(usr) ? usr : []);
      setOrgInfo(org);
      setSettings(st);
      setVersionInfo(ver);
      setBillingState(bill);
    } catch (err) {
      console.error('Error loading cloud dashboard data:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadAllData();
  }, []);

  const handleCheckoutPlan = async (planKey: string) => {
    try {
      setBillingActionMsg(null);
      const res = await api.createSubscriptionCheckout({
        plan_key: planKey,
        interval: selectedInterval
      });
      if (res.error) {
        setBillingActionMsg({ type: 'error', text: res.error });
      } else {
        setBillingActionMsg({
          type: 'success',
          text: `Subscription intent created for ${res.plan_name} (${res.interval}). Subscription ID: ${res.subscription_id}`
        });
        loadAllData();
      }
    } catch (err: any) {
      setBillingActionMsg({ type: 'error', text: err.message });
    }
  };

  const handleChangePlan = async (newPlanKey: string) => {
    try {
      setBillingActionMsg(null);
      const res = await api.changeSubscriptionPlan({
        new_plan_key: newPlanKey,
        interval: selectedInterval
      });
      if (res.error) {
        setBillingActionMsg({ type: 'error', text: res.error });
      } else {
        setBillingActionMsg({
          type: 'success',
          text: `Subscription updated to ${res.plan_name} (${res.interval}).`
        });
        loadAllData();
      }
    } catch (err: any) {
      setBillingActionMsg({ type: 'error', text: err.message });
    }
  };

  const handleCancelSub = async () => {
    if (!confirm('Are you sure you want to cancel your subscription? Your license will remain functional until the end of current period.')) return;
    try {
      setBillingActionMsg(null);
      const res = await api.cancelSubscription();
      if (res.error) {
        setBillingActionMsg({ type: 'error', text: res.error });
      } else {
        setBillingActionMsg({ type: 'success', text: 'Subscription has been cancelled.' });
        loadAllData();
      }
    } catch (err: any) {
      setBillingActionMsg({ type: 'error', text: err.message });
    }
  };

  const handleRevokeDevice = async (deviceId: string) => {
    if (!confirm(`Are you sure you want to revoke license access for device ${deviceId}?`)) return;
    try {
      await api.revokeCloudDevice(deviceId);
      loadAllData();
    } catch (e: any) {
      alert(`Failed to revoke device: ${e.message}`);
    }
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUsername || !newPassword) return;
    try {
      const res = await api.createCloudUser({
        username: newUsername,
        password: newPassword,
        role: newRole
      });
      if (res.error) {
        setUserActionMsg({ type: 'error', text: res.error });
      } else {
        setUserActionMsg({ type: 'success', text: `User ${newUsername} created successfully with role ${newRole}.` });
        setNewUsername('');
        setNewPassword('');
        loadAllData();
      }
    } catch (err: any) {
      setUserActionMsg({ type: 'error', text: err.message });
    }
  };

  const handleToggleUserDisable = async (userId: string) => {
    try {
      await api.toggleCloudUserDisable(userId);
      loadAllData();
    } catch (e: any) {
      alert(`Failed to update user status: ${e.message}`);
    }
  };

  const handleUpdateUserRole = async (userId: string, role: string) => {
    try {
      await api.updateCloudUserRole(userId, role);
      loadAllData();
    } catch (e: any) {
      alert(`Failed to update role: ${e.message}`);
    }
  };

  const handleRemoveUser = async (userId: string) => {
    if (!confirm(`Are you sure you want to delete user ${userId}? This action is permanent.`)) return;
    try {
      const res = await api.removeCloudUser(userId);
      if (res.error) {
        alert(res.error);
      } else {
        loadAllData();
      }
    } catch (e: any) {
      alert(`Failed to remove user: ${e.message}`);
    }
  };

  const handleVerifyReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!verifyQueryId.trim()) return;
    try {
      setVerifyLoading(true);
      const res = await api.verifyCloudReport(verifyQueryId.trim());
      setVerificationResult(res);
    } catch (err: any) {
      setVerificationResult({
        verified: false,
        match_status: 'ERROR',
        message: err.message || 'Failed to verify report'
      });
    } finally {
      setVerifyLoading(false);
    }
  };

  const navSections = [
    { id: 'overview', label: '1. Overview', icon: <TrendingUp className="w-4 h-4" /> },
    { id: 'scans', label: '2. Scan History', icon: <History className="w-4 h-4" /> },
    { id: 'trend', label: '3. Compliance Trend', icon: <Layers className="w-4 h-4" /> },
    { id: 'devices', label: '4. Device Management', icon: <Monitor className="w-4 h-4" /> },
    { id: 'users', label: '5. User Management', icon: <Users className="w-4 h-4" /> },
    { id: 'organization', label: '6. Organization Settings', icon: <Building className="w-4 h-4" /> },
    { id: 'billing', label: '7. Subscriptions & Billing', icon: <CreditCard className="w-4 h-4 text-emerald-400" /> },
    { id: 'privacy', label: '8. Privacy Telemetry', icon: <Lock className="w-4 h-4" /> },
    { id: 'version', label: '9. Software & Engine', icon: <Cpu className="w-4 h-4" /> },
    { id: 'verification', label: '10. Report Verification', icon: <FileCheck2 className="w-4 h-4" /> }
  ];

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-sm">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Cloud className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-slate-100 tracking-tight">
                FileSentinel Vendor Cloud Dashboard
              </h1>
              <span className="text-[10px] font-mono uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-2 py-0.5 rounded-full font-semibold">
                Cloud Telemetry Active
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Organization: <span className="font-semibold text-slate-200">{orgInfo?.organization_name || 'My Organization'}</span> ({orgInfo?.organization_id}) &bull; Local-First Zero Document Ingestion
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadAllData}
            disabled={refreshing}
            className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3.5 py-2 rounded-lg text-xs font-medium flex items-center gap-2 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            {refreshing ? 'Refreshing...' : 'Refresh Metrics'}
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-2 border-b border-slate-800 text-xs font-medium">
        {navSections.map(s => {
          const active = activeSection === s.id;
          return (
            <button
              key={s.id}
              onClick={() => {
                setActiveSection(s.id as any);
                if (s.id !== 'scans') setSelectedScanDetail(null);
              }}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg whitespace-nowrap transition-colors ${
                active
                  ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              {s.icon}
              {s.label}
            </button>
          );
        })}
      </div>

      {/* SECTION 1: OVERVIEW */}
      {activeSection === 'overview' && (
        <div className="space-y-6">
          {/* Main Score & Top Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
              <span className="text-[11px] font-mono text-slate-400 block uppercase tracking-wider">Current Compliance Score</span>
              <div className="flex items-baseline gap-3 mt-2">
                <span className="text-3xl font-extrabold font-mono text-emerald-400">
                  {overview?.current_score ?? 0}%
                </span>
                {overview?.score_change !== undefined && (
                  <span className={`text-xs font-mono font-medium flex items-center ${overview.score_change >= 0 ? 'text-emerald-400' : 'text-rose-400'}`}>
                    {overview.score_change >= 0 ? <ArrowUpRight className="w-3.5 h-3.5 mr-0.5" /> : <ArrowDownRight className="w-3.5 h-3.5 mr-0.5" />}
                    {overview.score_change >= 0 ? `+${overview.score_change}` : overview.score_change}%
                  </span>
                )}
              </div>
              <span className="text-[11px] text-slate-500 mt-1 block">
                Previous Score: {overview?.previous_score ?? 0}%
              </span>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <span className="text-[11px] font-mono text-slate-400 block uppercase tracking-wider">Total Scans Executed</span>
              <span className="text-3xl font-extrabold font-mono text-slate-100 block mt-2">
                {overview?.total_scans ?? 0}
              </span>
              <span className="text-[11px] text-slate-500 mt-1 block truncate">
                Last scan: {overview?.last_scan ? new Date(overview.last_scan).toLocaleString() : 'None'}
              </span>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <span className="text-[11px] font-mono text-slate-400 block uppercase tracking-wider">Total Files Scanned</span>
              <span className="text-3xl font-extrabold font-mono text-cyan-400 block mt-2">
                {(overview?.files_scanned ?? 0).toLocaleString()}
              </span>
              <span className="text-[11px] text-slate-500 mt-1 block">
                Zero document text stored on cloud
              </span>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <span className="text-[11px] font-mono text-slate-400 block uppercase tracking-wider">Active Plan & Status</span>
              <span className="text-xl font-bold font-mono text-emerald-400 block mt-2">
                {orgInfo?.plan || 'ENTERPRISE'}
              </span>
              <span className="text-[11px] text-emerald-400/80 mt-1 block">
                License Status: {orgInfo?.license_status || 'ACTIVE'}
              </span>
            </div>
          </div>

          {/* Compliance Breakdown Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Audit Status Counts */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
              <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                Audit Parameters Compliance Status
              </h3>
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-emerald-400 font-semibold flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5" /> PASS
                    </span>
                    <span className="text-lg font-bold font-mono text-slate-100">{overview?.pass_count ?? 0}</span>
                  </div>
                  <span className="text-[10px] text-slate-500 mt-0.5 block">Satisfies deterministic rules</span>
                </div>

                <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-amber-400 font-semibold flex items-center gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5" /> REVIEW
                    </span>
                    <span className="text-lg font-bold font-mono text-slate-100">{overview?.review_count ?? 0}</span>
                  </div>
                  <span className="text-[10px] text-slate-500 mt-0.5 block">Requires operator assessment</span>
                </div>

                <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-rose-400 font-semibold flex items-center gap-1.5">
                      <XCircle className="w-3.5 h-3.5" /> FAIL
                    </span>
                    <span className="text-lg font-bold font-mono text-slate-100">{overview?.fail_count ?? 0}</span>
                  </div>
                  <span className="text-[10px] text-slate-500 mt-0.5 block">Deterministic non-compliance</span>
                </div>

                <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-slate-400 font-semibold flex items-center gap-1.5">
                      <HelpCircle className="w-3.5 h-3.5" /> EVIDENCE_NOT_FOUND
                    </span>
                    <span className="text-lg font-bold font-mono text-slate-100">{overview?.evidence_not_found_count ?? 0}</span>
                  </div>
                  <span className="text-[10px] text-slate-500 mt-0.5 block">Missing mandatory evidence</span>
                </div>
              </div>
            </div>

            {/* Risk Breakdown Counts */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
              <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                Organization Risk Severity Breakdown
              </h3>
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-slate-950 border border-rose-900/30 rounded-lg p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-rose-400 font-semibold">Critical</span>
                    <span className="text-lg font-bold font-mono text-rose-400">{overview?.critical_count ?? 0}</span>
                  </div>
                  <span className="text-[10px] text-slate-500 mt-0.5 block">Immediate compliance risk</span>
                </div>

                <div className="bg-slate-950 border border-orange-900/30 rounded-lg p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-orange-400 font-semibold">High</span>
                    <span className="text-lg font-bold font-mono text-orange-400">{overview?.high_count ?? 0}</span>
                  </div>
                  <span className="text-[10px] text-slate-500 mt-0.5 block">Significant compliance risk</span>
                </div>

                <div className="bg-slate-950 border border-amber-900/30 rounded-lg p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-amber-400 font-semibold">Medium</span>
                    <span className="text-lg font-bold font-mono text-amber-400">{overview?.medium_count ?? 0}</span>
                  </div>
                  <span className="text-[10px] text-slate-500 mt-0.5 block">Standard policy checks</span>
                </div>

                <div className="bg-slate-950 border border-blue-900/30 rounded-lg p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-blue-400 font-semibold">Low</span>
                    <span className="text-lg font-bold font-mono text-blue-400">{overview?.low_count ?? 0}</span>
                  </div>
                  <span className="text-[10px] text-slate-500 mt-0.5 block">Advisory and hygiene items</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 2: SCAN HISTORY */}
      {activeSection === 'scans' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-200">Organization Scan History</h3>
                <p className="text-xs text-slate-400 mt-0.5">Aggregated privacy-preserving telemetry from registered organization endpoints.</p>
              </div>
              <span className="text-xs font-mono text-slate-400">{scans.length} scans recorded</span>
            </div>

            {scans.length === 0 ? (
              <div className="p-12 text-center text-slate-500">
                <History className="w-8 h-8 mx-auto mb-2 text-slate-600" />
                <p className="text-sm">No scan telemetry recorded for this organization yet.</p>
                <p className="text-xs text-slate-600 mt-1">Run a scan on any registered endpoint to populate telemetry records.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase font-mono text-[10px]">
                    <tr>
                      <th className="p-3">Scan ID</th>
                      <th className="p-3">Date</th>
                      <th className="p-3">User</th>
                      <th className="p-3">Device</th>
                      <th className="p-3">Files</th>
                      <th className="p-3">Score</th>
                      <th className="p-3">PASS</th>
                      <th className="p-3">REVIEW</th>
                      <th className="p-3">FAIL</th>
                      <th className="p-3">Status</th>
                      <th className="p-3">Duration</th>
                      <th className="p-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {scans.map(scan => (
                      <tr key={scan.scan_id} className="hover:bg-slate-800/40 transition-colors">
                        <td className="p-3 font-semibold text-slate-200">{scan.scan_id}</td>
                        <td className="p-3 text-slate-400">{new Date(scan.started_at).toLocaleString()}</td>
                        <td className="p-3 text-slate-300">{scan.user_id}</td>
                        <td className="p-3 text-slate-400">{scan.device_id}</td>
                        <td className="p-3 text-slate-300">{scan.files_processed}</td>
                        <td className="p-3">
                          <span className={`font-bold ${scan.overall_score >= 80 ? 'text-emerald-400' : scan.overall_score >= 60 ? 'text-amber-400' : 'text-rose-400'}`}>
                            {scan.overall_score}%
                          </span>
                        </td>
                        <td className="p-3 text-emerald-400">{scan.pass_count}</td>
                        <td className="p-3 text-amber-400">{scan.review_count}</td>
                        <td className="p-3 text-rose-400">{scan.fail_count}</td>
                        <td className="p-3">
                          <span className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded text-[10px]">
                            {scan.scan_status}
                          </span>
                        </td>
                        <td className="p-3 text-slate-400">{(scan.duration_ms / 1000).toFixed(1)}s</td>
                        <td className="p-3 text-right">
                          <button
                            onClick={() => setSelectedScanDetail(scan)}
                            className="bg-slate-800 hover:bg-slate-700 text-emerald-400 hover:text-emerald-300 px-2.5 py-1 rounded text-[11px] font-sans font-medium transition-colors"
                          >
                            View Aggregate
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* SECTION 3: SCAN DETAILS (MODAL / INLINE DRAWER) */}
          {selectedScanDetail && (
            <div className="bg-slate-900 border border-emerald-500/30 rounded-xl p-6 space-y-6">
              <div className="flex items-center justify-between pb-4 border-b border-slate-800">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-bold text-slate-100">Scan Session Aggregate Details</h3>
                    <span className="font-mono text-xs text-emerald-400 bg-emerald-950/60 border border-emerald-800/60 px-2 py-0.5 rounded">
                      {selectedScanDetail.scan_id}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">
                    Privacy Guarantee: Raw document contents, OCR text, and sensitive extracted fields are never collected or displayed.
                  </p>
                </div>
                <button
                  onClick={() => setSelectedScanDetail(null)}
                  className="text-slate-400 hover:text-slate-200 text-xs bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-lg transition-colors"
                >
                  Close Details
                </button>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
                  <span className="text-[10px] font-mono text-slate-400 uppercase block">Compliance Score</span>
                  <span className="text-xl font-bold font-mono text-emerald-400">{selectedScanDetail.overall_score}%</span>
                </div>
                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
                  <span className="text-[10px] font-mono text-slate-400 uppercase block">Files Processed</span>
                  <span className="text-xl font-bold font-mono text-slate-100">{selectedScanDetail.files_processed}</span>
                </div>
                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
                  <span className="text-[10px] font-mono text-slate-400 uppercase block">Parameters Evaluated</span>
                  <span className="text-xl font-bold font-mono text-slate-100">{selectedScanDetail.parameters_evaluated}</span>
                </div>
                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
                  <span className="text-[10px] font-mono text-slate-400 uppercase block">Execution Duration</span>
                  <span className="text-xl font-bold font-mono text-cyan-400">{(selectedScanDetail.duration_ms / 1000).toFixed(2)}s</span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-3">
                  <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Audit Result Metrics</h4>
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex justify-between py-1 border-b border-slate-800/80">
                      <span className="text-emerald-400">PASS Count</span>
                      <span className="font-bold text-slate-200">{selectedScanDetail.pass_count}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800/80">
                      <span className="text-amber-400">REVIEW Count</span>
                      <span className="font-bold text-slate-200">{selectedScanDetail.review_count}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800/80">
                      <span className="text-rose-400">FAIL Count</span>
                      <span className="font-bold text-slate-200">{selectedScanDetail.fail_count}</span>
                    </div>
                    <div className="flex justify-between py-1">
                      <span className="text-slate-400">EVIDENCE_NOT_FOUND</span>
                      <span className="font-bold text-slate-200">{selectedScanDetail.evidence_not_found_count}</span>
                    </div>
                  </div>
                </div>

                <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-3">
                  <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Device & Engine Specs</h4>
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex justify-between py-1 border-b border-slate-800/80">
                      <span className="text-slate-400">Application Version</span>
                      <span className="text-slate-200">{selectedScanDetail.application_version}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800/80">
                      <span className="text-slate-400">Engine Version</span>
                      <span className="text-slate-200">{selectedScanDetail.engine_version}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800/80">
                      <span className="text-slate-400">Checklist Version</span>
                      <span className="text-slate-200">{selectedScanDetail.checklist_version}</span>
                    </div>
                    <div className="flex justify-between py-1">
                      <span className="text-slate-400">OS Telemetry</span>
                      <span className="text-slate-200">{selectedScanDetail.device_telemetry?.os_family || 'Linux'} {selectedScanDetail.device_telemetry?.architecture || ''}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SECTION 4: COMPLIANCE TREND */}
      {activeSection === 'trend' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-slate-200">Compliance Score Trend Over Time</h3>
              <p className="text-xs text-slate-400 mt-0.5">Chronological progression of organizational audit scores across scan runs.</p>
            </div>
            <span className="text-xs font-mono text-emerald-400">{trend.length} historic runs</span>
          </div>

          {trend.length === 0 ? (
            <div className="p-12 text-center text-slate-500">
              <TrendingUp className="w-8 h-8 mx-auto mb-2 text-slate-600" />
              <p className="text-sm">No trend data available yet.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Visual Bar Graph */}
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-6">
                <div className="h-48 flex items-end gap-3 pt-6">
                  {trend.map((point, idx) => {
                    const heightPercent = Math.max(10, Math.min(100, point.score));
                    return (
                      <div key={idx} className="flex-1 flex flex-col items-center gap-2 group relative">
                        <div
                          style={{ height: `${heightPercent}%` }}
                          className={`w-full max-w-[36px] rounded-t transition-all ${
                            point.score >= 80 ? 'bg-emerald-500 hover:bg-emerald-400' : point.score >= 60 ? 'bg-amber-500 hover:bg-amber-400' : 'bg-rose-500 hover:bg-rose-400'
                          }`}
                        />
                        <span className="text-[10px] font-mono text-slate-400 truncate max-w-[48px]">
                          {new Date(point.date).toLocaleDateString(undefined, { month: 'numeric', day: 'numeric' })}
                        </span>

                        {/* Tooltip */}
                        <div className="absolute bottom-full mb-2 hidden group-hover:block bg-slate-900 border border-slate-700 p-2 rounded text-[11px] font-mono text-slate-200 whitespace-nowrap z-10 shadow-lg">
                          <div>Score: <span className="font-bold text-emerald-400">{point.score}%</span></div>
                          <div>Files: {point.files}</div>
                          <div>PASS: {point.pass} | FAIL: {point.fail}</div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Table view */}
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase text-[10px]">
                    <tr>
                      <th className="p-3">Date</th>
                      <th className="p-3">Scan ID</th>
                      <th className="p-3">Files</th>
                      <th className="p-3">Score</th>
                      <th className="p-3">PASS</th>
                      <th className="p-3">REVIEW</th>
                      <th className="p-3">FAIL</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {trend.map(t => (
                      <tr key={t.scan_id} className="hover:bg-slate-800/40">
                        <td className="p-3 text-slate-400">{new Date(t.date).toLocaleString()}</td>
                        <td className="p-3 text-slate-200 font-semibold">{t.scan_id}</td>
                        <td className="p-3 text-slate-300">{t.files}</td>
                        <td className="p-3">
                          <span className={`font-bold ${t.score >= 80 ? 'text-emerald-400' : t.score >= 60 ? 'text-amber-400' : 'text-rose-400'}`}>
                            {t.score}%
                          </span>
                        </td>
                        <td className="p-3 text-emerald-400">{t.pass}</td>
                        <td className="p-3 text-amber-400">{t.review}</td>
                        <td className="p-3 text-rose-400">{t.fail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SECTION 5: DEVICE MANAGEMENT */}
      {activeSection === 'devices' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-slate-200">Organization Device Fleet</h3>
              <p className="text-xs text-slate-400 mt-0.5">Manage registered endpoints, versions, and license revocation.</p>
            </div>
            <span className="text-xs font-mono text-slate-400">{devices.length} registered devices</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase font-mono text-[10px]">
                <tr>
                  <th className="p-3">Device ID</th>
                  <th className="p-3">Device Name</th>
                  <th className="p-3">Operating System</th>
                  <th className="p-3">App Version</th>
                  <th className="p-3">Last Seen</th>
                  <th className="p-3">License Status</th>
                  <th className="p-3">State</th>
                  <th className="p-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {devices.map(dev => (
                  <tr key={dev.device_id} className="hover:bg-slate-800/40">
                    <td className="p-3 font-semibold text-slate-200">{dev.device_id}</td>
                    <td className="p-3 text-slate-300 font-sans">{dev.device_name}</td>
                    <td className="p-3 text-slate-400">{dev.os}</td>
                    <td className="p-3 text-slate-300">{dev.application_version}</td>
                    <td className="p-3 text-slate-400">{dev.last_seen ? new Date(dev.last_seen).toLocaleString() : 'Never'}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        dev.license_status === 'ACTIVE'
                          ? 'bg-emerald-500/20 text-emerald-300'
                          : dev.license_status === 'REVOKED'
                          ? 'bg-rose-500/20 text-rose-300'
                          : 'bg-slate-800 text-slate-400'
                      }`}>
                        {dev.license_status}
                      </span>
                    </td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] ${
                        dev.revoked ? 'bg-rose-950 text-rose-400' : 'bg-emerald-950 text-emerald-400'
                      }`}>
                        {dev.revoked ? 'REVOKED' : 'ACTIVE'}
                      </span>
                    </td>
                    <td className="p-3 text-right font-sans">
                      {!dev.revoked && (
                        <button
                          onClick={() => handleRevokeDevice(dev.device_id)}
                          className="bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 px-2.5 py-1 rounded text-xs transition-colors"
                        >
                          Revoke Device
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SECTION 6: USER MANAGEMENT (ORG_ADMIN ONLY) */}
      {activeSection === 'users' && (
        <div className="space-y-6">
          {/* Create User Form */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
            <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <UserPlus className="w-4 h-4 text-emerald-400" />
              Create Organization User (ORG_ADMIN Only)
            </h3>

            {userActionMsg && (
              <div className={`p-3 rounded-lg text-xs font-mono ${
                userActionMsg.type === 'success' ? 'bg-emerald-950/60 border border-emerald-800 text-emerald-400' : 'bg-rose-950/60 border border-rose-800 text-rose-400'
              }`}>
                {userActionMsg.text}
              </div>
            )}

            <form onSubmit={handleCreateUser} className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div>
                <label className="text-xs text-slate-400 block mb-1">Username</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. auditor_john"
                  value={newUsername}
                  onChange={e => setNewUsername(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="text-xs text-slate-400 block mb-1">Password</label>
                <input
                  type="password"
                  required
                  placeholder="Strong password"
                  value={newPassword}
                  onChange={e => setNewPassword(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="text-xs text-slate-400 block mb-1">Assigned Role</label>
                <select
                  value={newRole}
                  onChange={e => setNewRole(e.target.value as any)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
                >
                  <option value="ORG_ADMIN">ORG_ADMIN (Full Admin)</option>
                  <option value="AUDITOR">AUDITOR (Compliance & Audit)</option>
                  <option value="OPERATOR">OPERATOR (Scanner Execution)</option>
                  <option value="VIEWER">VIEWER (Read-Only)</option>
                </select>
              </div>

              <div className="flex items-end">
                <button
                  type="submit"
                  className="w-full bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold px-4 py-2 rounded-lg text-xs transition-colors"
                >
                  Create User
                </button>
              </div>
            </form>
          </div>

          {/* User List Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-200">Organization User Accounts</h3>
                <p className="text-xs text-slate-400 mt-0.5">Role-based access control and status management.</p>
              </div>
              <span className="text-xs font-mono text-slate-400">{users.length} total users</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase font-mono text-[10px]">
                  <tr>
                    <th className="p-3">User ID</th>
                    <th className="p-3">Username</th>
                    <th className="p-3">Role</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Created At</th>
                    <th className="p-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {users.map(u => (
                    <tr key={u.user_id} className="hover:bg-slate-800/40">
                      <td className="p-3 font-semibold text-slate-200">{u.user_id}</td>
                      <td className="p-3 text-slate-200 font-bold font-sans">{u.username}</td>
                      <td className="p-3 font-sans">
                        <select
                          value={u.role}
                          onChange={e => handleUpdateUserRole(u.user_id, e.target.value)}
                          className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-xs text-emerald-400 focus:outline-none"
                        >
                          <option value="ORG_ADMIN">ORG_ADMIN</option>
                          <option value="AUDITOR">AUDITOR</option>
                          <option value="OPERATOR">OPERATOR</option>
                          <option value="VIEWER">VIEWER</option>
                        </select>
                      </td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          u.disabled ? 'bg-rose-950 text-rose-400' : 'bg-emerald-950 text-emerald-400'
                        }`}>
                          {u.disabled ? 'DISABLED' : 'ACTIVE'}
                        </span>
                      </td>
                      <td className="p-3 text-slate-400">{new Date(u.created_at).toLocaleString()}</td>
                      <td className="p-3 text-right font-sans space-x-2">
                        <button
                          onClick={() => handleToggleUserDisable(u.user_id)}
                          className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-2.5 py-1 rounded text-xs transition-colors"
                        >
                          {u.disabled ? 'Enable' : 'Disable'}
                        </button>
                        <button
                          onClick={() => handleRemoveUser(u.user_id)}
                          className="bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 px-2.5 py-1 rounded text-xs transition-colors"
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 7: ORGANIZATION SETTINGS */}
      {activeSection === 'organization' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <div>
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Building className="w-4 h-4 text-emerald-400" />
                Organization Profile & License Quotas
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">Commercial plan, device caps, user quotas, and scan usage metrics.</p>
            </div>
            <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/60 px-3 py-1 rounded-lg">
              Org ID: {orgInfo?.organization_id}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
              <span className="text-[11px] font-mono text-slate-400 block uppercase">Organization Name</span>
              <span className="text-lg font-bold text-slate-100 block mt-1">{orgInfo?.organization_name}</span>
              <span className="text-[11px] text-slate-500 mt-2 block">Created: {orgInfo?.created_at ? new Date(orgInfo.created_at).toLocaleDateString() : 'N/A'}</span>
            </div>

            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
              <span className="text-[11px] font-mono text-slate-400 block uppercase">Subscription Plan</span>
              <span className="text-lg font-bold font-mono text-emerald-400 block mt-1">{orgInfo?.plan}</span>
              <span className="text-[11px] text-emerald-400/80 mt-2 block">License Status: {orgInfo?.license_status}</span>
            </div>

            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
              <span className="text-[11px] font-mono text-slate-400 block uppercase">License Expiration</span>
              <span className="text-lg font-bold font-mono text-slate-200 block mt-1">
                {orgInfo?.expires_at ? new Date(orgInfo.expires_at).toLocaleDateString() : 'Perpetual / Active'}
              </span>
              <span className="text-[11px] text-slate-500 mt-2 block">Grace Period: {orgInfo?.grace_until ? new Date(orgInfo.grace_until).toLocaleDateString() : 'None'}</span>
            </div>
          </div>

          {/* Usage Meters */}
          <div className="space-y-4 pt-2">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Usage & Quotas</h4>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
                <div className="flex justify-between text-xs">
                  <span className="text-slate-400">User Usage</span>
                  <span className="font-mono font-bold text-slate-200">{orgInfo?.usage.users.current} / {orgInfo?.usage.users.max}</span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div
                    style={{ width: `${Math.min(100, ((orgInfo?.usage.users.current || 0) / (orgInfo?.usage.users.max || 1)) * 100)}%` }}
                    className="bg-emerald-500 h-full rounded-full"
                  />
                </div>
              </div>

              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
                <div className="flex justify-between text-xs">
                  <span className="text-slate-400">Device Usage</span>
                  <span className="font-mono font-bold text-slate-200">{orgInfo?.usage.devices.current} / {orgInfo?.usage.devices.max}</span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div
                    style={{ width: `${Math.min(100, ((orgInfo?.usage.devices.current || 0) / (orgInfo?.usage.devices.max || 1)) * 100)}%` }}
                    className="bg-cyan-500 h-full rounded-full"
                  />
                </div>
              </div>

              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
                <div className="flex justify-between text-xs">
                  <span className="text-slate-400">Monthly Scan Quota</span>
                  <span className="font-mono font-bold text-slate-200">{orgInfo?.usage.scans.used} / {orgInfo?.usage.scans.limit}</span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div
                    style={{ width: `${Math.min(100, ((orgInfo?.usage.scans.used || 0) / (orgInfo?.usage.scans.limit || 1)) * 100)}%` }}
                    className="bg-amber-500 h-full rounded-full"
                  />
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 7: SUBSCRIPTIONS & BILLING (COMMERCIAL PHASE 5) */}
      {activeSection === 'billing' && (
        <div className="space-y-6">
          {/* Top Status & Safe Client State Banner */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
              <div>
                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <CreditCard className="w-4 h-4 text-emerald-400" />
                  Subscription & Commercial License Synchronization
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Authoritative server-side Razorpay webhook integration &bull; Non-destructive grace periods &bull; Predictable local engine
                </p>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-400">Billing Interval:</span>
                <div className="bg-slate-950 p-1 rounded-lg border border-slate-800 flex items-center gap-1 text-xs">
                  <button
                    onClick={() => setSelectedInterval('MONTHLY')}
                    className={`px-3 py-1 rounded transition-colors ${
                      selectedInterval === 'MONTHLY'
                        ? 'bg-emerald-500/20 text-emerald-300 font-semibold border border-emerald-500/30'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Monthly
                  </button>
                  <button
                    onClick={() => setSelectedInterval('ANNUAL')}
                    className={`px-3 py-1 rounded transition-colors flex items-center gap-1 ${
                      selectedInterval === 'ANNUAL'
                        ? 'bg-emerald-500/20 text-emerald-300 font-semibold border border-emerald-500/30'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Annual
                    <span className="text-[10px] bg-emerald-500/20 text-emerald-400 px-1 rounded uppercase">Save 17%</span>
                  </button>
                </div>
              </div>
            </div>

            {billingActionMsg && (
              <div className={`mt-4 p-3 rounded-lg border text-xs flex items-center gap-2 ${
                billingActionMsg.type === 'success'
                  ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-200'
                  : 'bg-rose-950/40 border-rose-500/40 text-rose-200'
              }`}>
                {billingActionMsg.type === 'success' ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <AlertCircle className="w-4 h-4 text-rose-400" />}
                {billingActionMsg.text}
              </div>
            )}

            {/* Current Active Plan Overview */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-4">
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
                <span className="text-[11px] font-mono text-slate-400 block uppercase">Current Plan</span>
                <span className="text-lg font-bold font-mono text-emerald-400 block mt-1">
                  {billingState?.subscription?.plan_name || 'Starter Trial'}
                </span>
                <span className="text-[11px] text-slate-400 mt-2 block font-mono">
                  Interval: {billingState?.subscription?.billing_interval || 'MONTHLY'}
                </span>
              </div>

              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
                <span className="text-[11px] font-mono text-slate-400 block uppercase">Billing Status</span>
                <div className="mt-1 flex items-center gap-2">
                  <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold ${
                    billingState?.subscription?.status === 'ACTIVE'
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      : billingState?.subscription?.status === 'TRIAL'
                      ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                      : billingState?.subscription?.status === 'PAST_DUE'
                      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse'
                      : 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                  }`}>
                    {billingState?.subscription?.status || 'TRIAL'}
                  </span>
                </div>
                <span className="text-[11px] text-slate-400 mt-2 block">
                  Engine State: <span className="font-mono text-slate-200">{billingState?.license_ui_state}</span>
                </span>
              </div>

              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
                <span className="text-[11px] font-mono text-slate-400 block uppercase">Period Expiration</span>
                <span className="text-sm font-bold font-mono text-slate-200 block mt-1">
                  {billingState?.subscription?.current_period_end ? new Date(billingState.subscription.current_period_end).toLocaleDateString() : 'N/A'}
                </span>
                <span className="text-[11px] text-slate-400 mt-2 block">
                  {billingState?.days_remaining != null ? `${billingState.days_remaining} days remaining` : 'Active'}
                </span>
              </div>

              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
                <span className="text-[11px] font-mono text-slate-400 block uppercase">Grace Period Policy</span>
                <span className={`text-sm font-bold font-mono block mt-1 ${billingState?.subscription?.grace_until ? 'text-amber-400' : 'text-slate-300'}`}>
                  {billingState?.subscription?.grace_until ? new Date(billingState.subscription.grace_until).toLocaleDateString() : '7 Days Non-Destructive'}
                </span>
                <span className="text-[11px] text-emerald-400/80 mt-2 block">
                  Zero Local Data Deletion
                </span>
              </div>
            </div>

            {billingState?.subscription && (
              <div className="mt-4 flex items-center justify-between pt-4 border-t border-slate-800/80">
                <span className="text-xs text-slate-400">
                  Subscription ID: <span className="font-mono text-slate-300">{billingState.subscription.subscription_id}</span>
                </span>
                <button
                  onClick={handleCancelSub}
                  className="bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 px-3 py-1.5 rounded-lg text-xs transition-colors"
                >
                  Cancel Subscription
                </button>
              </div>
            )}
          </div>

          {/* Centralized Plan Matrix */}
          <div>
            <h4 className="text-sm font-bold text-slate-200 mb-3 flex items-center gap-2">
              <Zap className="w-4 h-4 text-amber-400" />
              Available Plans & Upgrades
            </h4>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {billingState?.available_plans.map(p => {
                const isCurrent = billingState.subscription?.plan_id === p.plan_id;
                const priceFormatted = selectedInterval === 'ANNUAL'
                  ? (p.pricing.annual_inr / 100).toLocaleString('en-IN')
                  : (p.pricing.monthly_inr / 100).toLocaleString('en-IN');

                return (
                  <div
                    key={p.key}
                    className={`bg-slate-900 rounded-2xl border p-6 flex flex-col justify-between relative transition-all ${
                      isCurrent
                        ? 'border-emerald-500/60 shadow-lg shadow-emerald-950/20 ring-1 ring-emerald-500/30'
                        : 'border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    {isCurrent && (
                      <span className="absolute -top-3 left-6 bg-emerald-500 text-slate-950 text-[10px] font-mono font-bold uppercase px-2.5 py-0.5 rounded-full shadow">
                        Current Active Plan
                      </span>
                    )}

                    <div className="space-y-4">
                      <div>
                        <h4 className="text-base font-bold text-slate-100">{p.name}</h4>
                        <div className="mt-2 flex items-baseline gap-1">
                          <span className="text-2xl font-black font-mono text-slate-100">
                            {p.pricing.monthly_inr === 0 ? 'Free' : `₹${priceFormatted}`}
                          </span>
                          {p.pricing.monthly_inr > 0 && (
                            <span className="text-xs text-slate-400 font-sans">
                              /{selectedInterval === 'ANNUAL' ? 'yr' : 'mo'}
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="space-y-2 border-t border-slate-800 pt-4 text-xs">
                        <div className="flex justify-between text-slate-300">
                          <span className="text-slate-400">Device Quota:</span>
                          <span className="font-mono font-bold text-slate-200">{p.max_devices} Devices</span>
                        </div>
                        <div className="flex justify-between text-slate-300">
                          <span className="text-slate-400">User Seats:</span>
                          <span className="font-mono font-bold text-slate-200">{p.max_users} Users</span>
                        </div>
                        <div className="flex justify-between text-slate-300">
                          <span className="text-slate-400">Scan Limit:</span>
                          <span className="font-mono font-bold text-slate-200">
                            {p.scan_limit === -1 ? 'Unlimited' : `${p.scan_limit} Scans/mo`}
                          </span>
                        </div>
                      </div>

                      <div className="border-t border-slate-800 pt-4 space-y-2">
                        <span className="text-[11px] font-mono text-slate-400 block uppercase">Features Included</span>
                        <div className="space-y-1.5">
                          {p.feature_flags.map(f => (
                            <div key={f} className="flex items-center gap-2 text-xs text-slate-300">
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                              <span>{f.replace(/_/g, ' ')}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>

                    <div className="mt-6 pt-4 border-t border-slate-800">
                      {isCurrent ? (
                        <button
                          disabled
                          className="w-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-bold py-2.5 rounded-xl text-xs disabled:opacity-80"
                        >
                          Current Subscription
                        </button>
                      ) : (
                        <button
                          onClick={() => {
                            if (billingState.subscription) {
                              handleChangePlan(p.key);
                            } else {
                              handleCheckoutPlan(p.key);
                            }
                          }}
                          className="w-full bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold py-2.5 rounded-xl text-xs transition-colors flex items-center justify-center gap-2"
                        >
                          <Zap className="w-3.5 h-3.5" />
                          {billingState.subscription ? `Switch to ${p.key}` : `Activate ${p.key}`}
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Payment History Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
            <h4 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <History className="w-4 h-4 text-slate-400" />
              Recent Payment & Webhook Transactions
            </h4>

            {billingState?.recent_payments && billingState.recent_payments.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                    <tr>
                      <th className="p-3">Payment ID</th>
                      <th className="p-3">Amount</th>
                      <th className="p-3">Currency</th>
                      <th className="p-3">Status</th>
                      <th className="p-3">Processed At</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {billingState.recent_payments.map(p => (
                      <tr key={p.payment_id} className="hover:bg-slate-800/30">
                        <td className="p-3 text-slate-200">{p.payment_id}</td>
                        <td className="p-3 font-bold text-slate-100">₹{p.amount_formatted}</td>
                        <td className="p-3 text-slate-400">{p.currency}</td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            p.status === 'SUCCESS'
                              ? 'bg-emerald-500/20 text-emerald-300'
                              : 'bg-rose-500/20 text-rose-300'
                          }`}>
                            {p.status}
                          </span>
                        </td>
                        <td className="p-3 text-slate-400">{new Date(p.processed_at).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-6 text-center text-xs text-slate-500 font-mono bg-slate-950 rounded-lg border border-slate-800">
                No external Razorpay webhook payment transactions recorded yet.
              </div>
            )}
          </div>
        </div>
      )}

      {/* SECTION 8: PRIVACY SETTINGS */}
      {activeSection === 'privacy' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <div>
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Lock className="w-4 h-4 text-emerald-400" />
                Privacy Telemetry Configuration
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">Strict privacy boundaries and telemetry collection rules.</p>
            </div>
            <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/60 px-3 py-1 rounded-lg">
              Local-First Zero Leakage Standard
            </span>
          </div>

          <div className="space-y-4 text-xs font-sans">
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex items-start justify-between">
              <div>
                <span className="font-bold text-slate-200 block">Scan Telemetry Collection</span>
                <p className="text-slate-400 mt-0.5">Collects aggregate counts, compliance score, and coarse device metrics.</p>
                <p className="text-emerald-400 text-[11px] mt-1">Status: {settings?.telemetryEnabled !== false ? 'Enabled' : 'Disabled'}</p>
              </div>
              <span className={`px-2.5 py-1 rounded font-mono font-bold text-[11px] ${settings?.telemetryEnabled !== false ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-800 text-slate-400'}`}>
                {settings?.telemetryEnabled !== false ? 'ACTIVE' : 'OFF'}
              </span>
            </div>

            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex items-start justify-between">
              <div>
                <span className="font-bold text-slate-200 block">Diagnostic Crash Reporting</span>
                <p className="text-slate-400 mt-0.5">Sends anonymous stack traces upon unexpected scanner engine exceptions.</p>
                <p className="text-slate-400 text-[11px] mt-1">Status: {settings?.crashReportingEnabled ? 'Enabled' : 'Disabled'}</p>
              </div>
              <span className={`px-2.5 py-1 rounded font-mono font-bold text-[11px] ${settings?.crashReportingEnabled ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-800 text-slate-400'}`}>
                {settings?.crashReportingEnabled ? 'ACTIVE' : 'OFF'}
              </span>
            </div>

            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex items-start justify-between">
              <div>
                <span className="font-bold text-slate-200 block">Debug Filename Opt-In</span>
                <p className="text-slate-400 mt-0.5">Sanitized base filename transmission (disabled by default to protect customer naming privacy).</p>
                <p className="text-slate-400 text-[11px] mt-1">Status: {settings?.debugFilenamesEnabled ? 'Opted In' : 'Disabled (Standard Safe)'}</p>
              </div>
              <span className={`px-2.5 py-1 rounded font-mono font-bold text-[11px] ${settings?.debugFilenamesEnabled ? 'bg-amber-500/20 text-amber-300' : 'bg-slate-800 text-slate-400'}`}>
                {settings?.debugFilenamesEnabled ? 'OPTED IN' : 'DISABLED'}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 9: SOFTWARE VERSION */}
      {activeSection === 'version' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <div>
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Cpu className="w-4 h-4 text-emerald-400" />
                Software & Audit Engine Versions
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">Local deterministic engine release details and update status.</p>
            </div>
            <span className="text-xs font-mono text-slate-400">Release Channel: {versionInfo?.channel || 'production-stable'}</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
              <span className="text-[11px] font-mono text-slate-400 uppercase block">Current Agent Version</span>
              <span className="text-2xl font-bold font-mono text-slate-100 block mt-1">{versionInfo?.current_version || '1.0.0'}</span>
              <span className="text-[11px] text-emerald-400 mt-2 block">Deterministic local auditor runtime</span>
            </div>

            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
              <span className="text-[11px] font-mono text-slate-400 uppercase block">Latest Available Version</span>
              <span className="text-2xl font-bold font-mono text-emerald-400 block mt-1">{versionInfo?.latest_version || '1.0.0'}</span>
              <span className="text-[11px] text-slate-500 mt-2 block">
                {versionInfo?.update_available ? 'An update is available' : 'Up to date with vendor channel'}
              </span>
            </div>

            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
              <span className="text-[11px] font-mono text-slate-400 uppercase block">Checklist Policy Matrix</span>
              <span className="text-2xl font-bold font-mono text-cyan-400 block mt-1">{versionInfo?.checklist_version || '2026.1'}</span>
              <span className="text-[11px] text-slate-500 mt-2 block">Release: {versionInfo?.release_date || '2026-08-15'}</span>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 10: REPORT VERIFICATION */}
      {activeSection === 'verification' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <div>
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <FileCheck2 className="w-4 h-4 text-emerald-400" />
                Audit Report Verification & Authenticity Check
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Verify whether an exported audit report or scan ID matches the immutable server audit record.
              </p>
            </div>
          </div>

          <form onSubmit={handleVerifyReport} className="flex gap-3">
            <div className="flex-1 relative">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                required
                placeholder="Enter Report ID (e.g. AUDIT-...) or Scan ID (e.g. SCAN-...)"
                value={verifyQueryId}
                onChange={e => setVerifyQueryId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-emerald-500"
              />
            </div>
            <button
              type="submit"
              disabled={verifyLoading}
              className="bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold px-5 py-2.5 rounded-lg text-xs transition-colors flex items-center gap-2 disabled:opacity-50"
            >
              <FileCheck2 className="w-4 h-4" />
              {verifyLoading ? 'Verifying...' : 'Verify Report'}
            </button>
          </form>

          {verificationResult && (
            <div className={`p-6 rounded-xl border space-y-4 ${
              verificationResult.verified
                ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-200'
                : 'bg-rose-950/20 border-rose-500/40 text-rose-200'
            }`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {verificationResult.verified ? (
                    <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                  ) : (
                    <XCircle className="w-6 h-6 text-rose-400" />
                  )}
                  <div>
                    <h4 className="text-sm font-bold text-slate-100">
                      {verificationResult.verified ? 'Audit Report Authenticity Confirmed' : 'Verification Unsuccessful'}
                    </h4>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Match Status: <span className="font-mono font-bold text-slate-200">{verificationResult.match_status}</span>
                    </p>
                  </div>
                </div>

                <span className={`px-3 py-1 rounded text-xs font-mono font-bold ${
                  verificationResult.verified ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'
                }`}>
                  {verificationResult.verified ? 'VERIFIED' : 'UNVERIFIED'}
                </span>
              </div>

              {verificationResult.message && (
                <p className="text-xs font-mono text-slate-400 bg-slate-950/80 p-3 rounded-lg border border-slate-800">
                  {verificationResult.message}
                </p>
              )}

              {verificationResult.verified && (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono pt-2">
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block text-[10px] uppercase">Compliance Score</span>
                    <span className="text-emerald-400 text-base font-bold">{verificationResult.overall_score}%</span>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block text-[10px] uppercase">Audit Parameters</span>
                    <span className="text-slate-200 text-sm font-bold">
                      {verificationResult.pass_count} PASS / {verificationResult.fail_count} FAIL
                    </span>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block text-[10px] uppercase">Audit Date / Timestamp</span>
                    <span className="text-slate-200 text-xs truncate block">
                      {verificationResult.audit_date || verificationResult.completed_at ? new Date(verificationResult.audit_date || verificationResult.completed_at!).toLocaleString() : 'N/A'}
                    </span>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block text-[10px] uppercase">Checklist Version</span>
                    <span className="text-cyan-400 text-xs block">{verificationResult.checklist_version || '2026.1'}</span>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
