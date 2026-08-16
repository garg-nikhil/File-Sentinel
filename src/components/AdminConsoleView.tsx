import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  Building2,
  Users,
  Smartphone,
  KeyRound,
  CreditCard,
  BarChart3,
  AlertOctagon,
  Server,
  Search,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Plus,
  Lock,
  Unlock,
  RotateCcw,
  Zap,
  Clock,
  Check
} from 'lucide-react';

export const AdminConsoleView: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<
    'organizations' | 'users' | 'devices' | 'licenses' | 'subscriptions' | 'usage' | 'security' | 'system'
  >('organizations');

  const [orgs, setOrgs] = useState<any[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<any | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  const [users, setUsers] = useState<any[]>([]);
  const [devices, setDevices] = useState<any[]>([]);
  const [licenses, setLicenses] = useState<any[]>([]);
  const [subscriptions, setSubscriptions] = useState<any[]>([]);
  const [usage, setUsage] = useState<any | null>(null);
  const [securityEvents, setSecurityEvents] = useState<any[]>([]);
  const [systemInfo, setSystemInfo] = useState<any | null>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Issue License Modal state
  const [showIssueModal, setShowIssueModal] = useState(false);
  const [newLicenseOrgId, setNewLicenseOrgId] = useState('');
  const [newLicensePlanId, setNewLicensePlanId] = useState('plan-enterprise');
  const [newLicenseDays, setNewLicenseDays] = useState(365);

  // Password Reset modal result state
  const [tempPasswordResult, setTempPasswordResult] = useState<{ username: string; temp_password: string } | null>(null);

  const token = localStorage.getItem('filesentinel_token') || '';
  const headers = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  };

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      if (activeSubTab === 'organizations') {
        const res = await fetch(`/api/admin/organizations?search=${encodeURIComponent(searchQuery)}`, { headers });
        if (!res.ok) throw new Error('Failed to fetch organizations (Ensure you are logged in as SYS_ADMIN)');
        const data = await res.json();
        setOrgs(data);
      } else if (activeSubTab === 'users') {
        const res = await fetch('/api/admin/users', { headers });
        if (!res.ok) throw new Error('Failed to fetch users');
        const data = await res.json();
        setUsers(data);
      } else if (activeSubTab === 'devices') {
        const res = await fetch('/api/admin/devices', { headers });
        if (!res.ok) throw new Error('Failed to fetch devices');
        const data = await res.json();
        setDevices(data);
      } else if (activeSubTab === 'licenses') {
        const res = await fetch('/api/admin/licenses', { headers });
        if (!res.ok) throw new Error('Failed to fetch licenses');
        const data = await res.json();
        setLicenses(data);
      } else if (activeSubTab === 'subscriptions') {
        const res = await fetch('/api/admin/subscriptions', { headers });
        if (!res.ok) throw new Error('Failed to fetch subscriptions');
        const data = await res.json();
        setSubscriptions(data);
      } else if (activeSubTab === 'usage') {
        const res = await fetch('/api/admin/usage', { headers });
        if (!res.ok) throw new Error('Failed to fetch usage metrics');
        const data = await res.json();
        setUsage(data);
      } else if (activeSubTab === 'security') {
        const res = await fetch('/api/admin/security/events?limit=150', { headers });
        if (!res.ok) throw new Error('Failed to fetch security audit events');
        const data = await res.json();
        setSecurityEvents(data);
      } else if (activeSubTab === 'system') {
        const res = await fetch('/api/admin/system/info', { headers });
        if (!res.ok) throw new Error('Failed to fetch system info');
        const data = await res.json();
        setSystemInfo(data);
      }
    } catch (err: any) {
      setError(err.message || 'Admin action failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [activeSubTab]);

  const handleSearchOrg = (e: React.FormEvent) => {
    e.preventDefault();
    fetchData();
  };

  const handleOrgAction = async (orgId: string, action: 'suspend' | 'reactivate') => {
    try {
      const res = await fetch(`/api/admin/organizations/${orgId}/${action}`, { method: 'POST', headers });
      if (!res.ok) throw new Error(`Failed to ${action} organization`);
      setSuccessMessage(`Organization successfully ${action}d`);
      fetchData();
      if (selectedOrg && selectedOrg.organization.org_id === orgId) {
        handleViewOrgDetails(orgId);
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleViewOrgDetails = async (orgId: string) => {
    try {
      const res = await fetch(`/api/admin/organizations/${orgId}`, { headers });
      if (!res.ok) throw new Error('Failed to fetch organization details');
      const data = await res.json();
      setSelectedOrg(data);
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleUserDisable = async (userId: string, currentDisabled: number) => {
    try {
      const newDisabled = currentDisabled ? 0 : 1;
      const res = await fetch(`/api/admin/users/${userId}/disable`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ disabled: newDisabled })
      });
      if (!res.ok) throw new Error('Failed to update user status');
      setSuccessMessage(`User status updated successfully`);
      fetchData();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleResetPassword = async (userId: string, username: string) => {
    try {
      const res = await fetch(`/api/admin/users/${userId}/reset-recovery`, { method: 'POST', headers });
      if (!res.ok) throw new Error('Failed to generate recovery reset');
      const data = await res.json();
      setTempPasswordResult({ username, temp_password: data.temporary_password });
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleDeviceRevoke = async (deviceId: string, currentRevoked: number) => {
    try {
      const newRevoked = currentRevoked ? 0 : 1;
      const res = await fetch(`/api/admin/devices/${deviceId}/revoke`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ revoked: newRevoked })
      });
      if (!res.ok) throw new Error('Failed to update device status');
      setSuccessMessage('Device status updated successfully');
      fetchData();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleIssueLicense = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/admin/licenses/issue', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          organization_id: newLicenseOrgId,
          plan_id: newLicensePlanId,
          duration_days: Number(newLicenseDays)
        })
      });
      if (!res.ok) throw new Error('Failed to issue license');
      setSuccessMessage('License issued successfully');
      setShowIssueModal(false);
      setNewLicenseOrgId('');
      fetchData();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleLicenseStatus = async (licenseId: string, status: string) => {
    try {
      const res = await fetch(`/api/admin/licenses/${licenseId}/status`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ status })
      });
      if (!res.ok) throw new Error('Failed to update license status');
      setSuccessMessage(`License status updated to ${status}`);
      fetchData();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleExtendLicense = async (licenseId: string) => {
    try {
      const res = await fetch(`/api/admin/licenses/${licenseId}/extend`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ additional_days: 90 })
      });
      if (!res.ok) throw new Error('Failed to extend license');
      setSuccessMessage('License extended by 90 days');
      fetchData();
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <div className="flex-1 bg-slate-950 text-slate-100 flex flex-col h-screen overflow-hidden">
      {/* Top Header */}
      <header className="bg-slate-900 border-b border-slate-800 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              FileSentinel Internal Admin Console
              <span className="text-[10px] font-mono bg-rose-500/20 text-rose-300 px-2 py-0.5 rounded border border-rose-500/30">
                RESTRICTED: SYS_ADMIN
              </span>
            </h1>
            <p className="text-xs text-slate-400">Commercial Operations, Tenant Management, License Control & Telemetry Auditing</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchData}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg border border-slate-700 flex items-center gap-1.5 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
        </div>
      </header>

      {/* Notifications */}
      {error && (
        <div className="bg-rose-500/10 border-b border-rose-500/30 px-6 py-3 text-rose-300 text-sm flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-rose-400 hover:text-rose-200 text-xs font-bold">Dismiss</button>
        </div>
      )}
      {successMessage && (
        <div className="bg-emerald-500/10 border-b border-emerald-500/30 px-6 py-3 text-emerald-300 text-sm flex items-center justify-between">
          <span>{successMessage}</span>
          <button onClick={() => setSuccessMessage(null)} className="text-emerald-400 hover:text-emerald-200 text-xs font-bold">Dismiss</button>
        </div>
      )}

      {/* Temporary Password Modal result */}
      {tempPasswordResult && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <KeyRound className="w-5 h-5 text-indigo-400" /> Password Recovery / Reset Generated
            </h3>
            <p className="text-xs text-slate-400">
              A secure temporary recovery credential has been generated for user <strong className="text-slate-200">{tempPasswordResult.username}</strong>:
            </p>
            <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono text-emerald-400 text-sm tracking-wide select-all text-center">
              {tempPasswordResult.temp_password}
            </div>
            <p className="text-[11px] text-amber-400">
              Warning: Provide this credential securely to the user. It will not be shown again.
            </p>
            <div className="flex justify-end pt-2">
              <button
                onClick={() => setTempPasswordResult(null)}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold rounded-xl transition-colors"
              >
                Close & Acknowledge
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Sub-tab Navigation */}
      <div className="bg-slate-900/60 border-b border-slate-800 px-6 flex items-center gap-2 overflow-x-auto">
        {[
          { id: 'organizations', label: 'Organizations', icon: <Building2 className="w-4 h-4" /> },
          { id: 'users', label: 'Users & Roles', icon: <Users className="w-4 h-4" /> },
          { id: 'devices', label: 'Devices', icon: <Smartphone className="w-4 h-4" /> },
          { id: 'licenses', label: 'Licenses', icon: <KeyRound className="w-4 h-4" /> },
          { id: 'subscriptions', label: 'Subscriptions', icon: <CreditCard className="w-4 h-4" /> },
          { id: 'usage', label: 'Usage & Telemetry', icon: <BarChart3 className="w-4 h-4" /> },
          { id: 'security', label: 'Security & Audits', icon: <AlertOctagon className="w-4 h-4" /> },
          { id: 'system', label: 'System & Updates', icon: <Server className="w-4 h-4" /> }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => {
              setActiveSubTab(tab.id as any);
              setSelectedOrg(null);
            }}
            className={`px-4 py-3 text-xs font-semibold flex items-center gap-2 border-b-2 transition-colors whitespace-nowrap ${
              activeSubTab === tab.id
                ? 'border-indigo-500 text-indigo-400 bg-indigo-500/10'
                : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            {tab.icon} {tab.label}
          </button>
        ))}
      </div>

      {/* Main Content Area */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* ORGANIZATIONS TAB */}
        {activeSubTab === 'organizations' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <form onSubmit={handleSearchOrg} className="flex items-center gap-2">
                <div className="relative">
                  <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    placeholder="Search organizations by name or ID..."
                    value={searchQuery}
                    onChange={e => setSearchQuery(e.target.value)}
                    className="bg-slate-900 border border-slate-800 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-200 w-80 focus:outline-none focus:border-indigo-500"
                  />
                </div>
                <button type="submit" className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold rounded-xl border border-slate-700">
                  Search
                </button>
              </form>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Org List */}
              <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
                <div className="px-5 py-4 border-b border-slate-800 text-xs font-bold text-slate-300 uppercase tracking-wider">
                  Registered Organizations ({orgs.length})
                </div>
                <div className="divide-y divide-slate-800/60 overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950/60 text-slate-400 uppercase font-mono text-[10px]">
                      <tr>
                        <th className="px-4 py-3">Organization</th>
                        <th className="px-4 py-3">Status</th>
                        <th className="px-4 py-3">Users / Devices</th>
                        <th className="px-4 py-3">License</th>
                        <th className="px-4 py-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/40">
                      {orgs.map(org => (
                        <tr key={org.org_id} className="hover:bg-slate-800/40 transition-colors">
                          <td className="px-4 py-3">
                            <div className="font-bold text-slate-200">{org.name}</div>
                            <div className="font-mono text-[10px] text-slate-500">{org.org_id}</div>
                          </td>
                          <td className="px-4 py-3">
                            {org.suspended ? (
                              <span className="px-2 py-0.5 bg-rose-500/20 text-rose-300 rounded text-[10px] font-bold border border-rose-500/30">SUSPENDED</span>
                            ) : (
                              <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-300 rounded text-[10px] font-bold border border-emerald-500/30">ACTIVE</span>
                            )}
                          </td>
                          <td className="px-4 py-3 text-slate-300">
                            {org.user_count} users / {org.device_count} devices
                          </td>
                          <td className="px-4 py-3">
                            <span className="font-mono text-[11px] text-indigo-400">{org.license_status || 'NO_LICENSE'}</span>
                          </td>
                          <td className="px-4 py-3 text-right space-x-2">
                            <button
                              onClick={() => handleViewOrgDetails(org.org_id)}
                              className="px-2.5 py-1 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-400 font-bold rounded-lg border border-indigo-500/30"
                            >
                              Inspect
                            </button>
                            {org.suspended ? (
                              <button
                                onClick={() => handleOrgAction(org.org_id, 'reactivate')}
                                className="px-2.5 py-1 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 font-bold rounded-lg border border-emerald-500/30"
                              >
                                Reactivate
                              </button>
                            ) : (
                              <button
                                onClick={() => handleOrgAction(org.org_id, 'suspend')}
                                className="px-2.5 py-1 bg-rose-600/20 hover:bg-rose-600/30 text-rose-400 font-bold rounded-lg border border-rose-500/30"
                              >
                                Suspend
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Selected Org Details Drawer */}
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4 shadow-xl">
                <div className="text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-3">
                  Organization Inspector
                </div>
                {selectedOrg ? (
                  <div className="space-y-4 text-xs">
                    <div>
                      <div className="text-slate-500">Organization Name</div>
                      <div className="text-base font-bold text-slate-100">{selectedOrg.organization.name}</div>
                      <div className="font-mono text-[10px] text-slate-500">{selectedOrg.organization.org_id}</div>
                    </div>

                    <div className="grid grid-cols-2 gap-3 bg-slate-950 p-3 rounded-xl border border-slate-800">
                      <div>
                        <div className="text-slate-500 text-[10px]">Users</div>
                        <div className="text-sm font-bold text-slate-200">{selectedOrg.users.length}</div>
                      </div>
                      <div>
                        <div className="text-slate-500 text-[10px]">Devices</div>
                        <div className="text-sm font-bold text-slate-200">{selectedOrg.devices.length}</div>
                      </div>
                    </div>

                    <div>
                      <div className="font-bold text-slate-300 mb-1">Licenses ({selectedOrg.licenses.length})</div>
                      <div className="space-y-2">
                        {selectedOrg.licenses.map((l: any) => (
                          <div key={l.license_id} className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-[11px]">
                            <div className="flex justify-between font-mono">
                              <span className="text-indigo-400">{l.license_id}</span>
                              <span className="text-emerald-400">{l.status}</span>
                            </div>
                            <div className="text-slate-400 mt-1">Expires: {new Date(l.expires_at).toLocaleDateString()}</div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div>
                      <div className="font-bold text-slate-300 mb-1">Recent Scans ({selectedOrg.recent_scans.length})</div>
                      <div className="space-y-1.5 max-h-48 overflow-y-auto">
                        {selectedOrg.recent_scans.map((s: any) => (
                          <div key={s.scan_id} className="bg-slate-950 px-3 py-2 rounded-lg border border-slate-800 flex justify-between items-center text-[11px]">
                            <span className="font-mono text-slate-400">{s.scan_id.substring(0, 12)}...</span>
                            <span className={s.status === 'SUCCESS' ? 'text-emerald-400' : 'text-amber-400'}>{s.status}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-12 text-slate-500 text-xs">
                    Select an organization to inspect users, devices, licenses, and recent scans.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* USERS TAB */}
        {activeSubTab === 'users' && (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
            <div className="px-5 py-4 border-b border-slate-800 text-xs font-bold text-slate-300 uppercase tracking-wider flex justify-between items-center">
              <span>All Users & Role Inspection ({users.length})</span>
            </div>
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 uppercase font-mono text-[10px]">
                <tr>
                  <th className="px-4 py-3">User</th>
                  <th className="px-4 py-3">Organization</th>
                  <th className="px-4 py-3">Role</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40">
                {users.map(u => (
                  <tr key={u.user_id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3">
                      <div className="font-bold text-slate-200">{u.username}</div>
                      <div className="font-mono text-[10px] text-slate-500">{u.user_id}</div>
                    </td>
                    <td className="px-4 py-3 text-slate-300">{u.org_name}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono border ${
                        u.role === 'SYS_ADMIN'
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                          : u.role === 'ORG_ADMIN'
                          ? 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30'
                          : 'bg-slate-800 text-slate-300 border-slate-700'
                      }`}>
                        {u.role}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {u.disabled ? (
                        <span className="px-2 py-0.5 bg-rose-500/20 text-rose-300 rounded text-[10px] font-bold">DISABLED</span>
                      ) : (
                        <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-300 rounded text-[10px] font-bold">ACTIVE</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right space-x-2">
                      <button
                        onClick={() => handleResetPassword(u.user_id, u.username)}
                        className="px-2.5 py-1 bg-amber-600/20 hover:bg-amber-600/30 text-amber-400 font-bold rounded-lg border border-amber-500/30"
                        title="Reset/Recovery Workflow"
                      >
                        Reset Password
                      </button>
                      <button
                        onClick={() => handleUserDisable(u.user_id, u.disabled)}
                        className={`px-2.5 py-1 font-bold rounded-lg border ${
                          u.disabled
                            ? 'bg-emerald-600/20 text-emerald-400 border-emerald-500/30 hover:bg-emerald-600/30'
                            : 'bg-rose-600/20 text-rose-400 border-rose-500/30 hover:bg-rose-600/30'
                        }`}
                      >
                        {u.disabled ? 'Enable' : 'Disable'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* DEVICES TAB */}
        {activeSubTab === 'devices' && (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
            <div className="px-5 py-4 border-b border-slate-800 text-xs font-bold text-slate-300 uppercase tracking-wider">
              Registered Devices ({devices.length})
            </div>
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 uppercase font-mono text-[10px]">
                <tr>
                  <th className="px-4 py-3">Device Name</th>
                  <th className="px-4 py-3">Organization</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Registered At</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40">
                {devices.map(d => (
                  <tr key={d.device_id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3">
                      <div className="font-bold text-slate-200">{d.device_name}</div>
                      <div className="font-mono text-[10px] text-slate-500">{d.device_id}</div>
                    </td>
                    <td className="px-4 py-3 text-slate-300">{d.org_name}</td>
                    <td className="px-4 py-3">
                      {d.revoked ? (
                        <span className="px-2 py-0.5 bg-rose-500/20 text-rose-300 rounded text-[10px] font-bold">REVOKED</span>
                      ) : (
                        <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-300 rounded text-[10px] font-bold">ACTIVE</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-400">{new Date(d.registered_at).toLocaleString()}</td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => handleDeviceRevoke(d.device_id, d.revoked)}
                        className={`px-2.5 py-1 font-bold rounded-lg border ${
                          d.revoked
                            ? 'bg-emerald-600/20 text-emerald-400 border-emerald-500/30'
                            : 'bg-rose-600/20 text-rose-400 border-rose-500/30'
                        }`}
                      >
                        {d.revoked ? 'Reactivate' : 'Revoke'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* LICENSES TAB */}
        {activeSubTab === 'licenses' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <div className="text-xs font-bold text-slate-300 uppercase tracking-wider">Enterprise Licenses ({licenses.length})</div>
              <button
                onClick={() => setShowIssueModal(true)}
                className="px-3.5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold rounded-xl flex items-center gap-1.5 transition-colors shadow-lg"
              >
                <Plus className="w-4 h-4" /> Issue New License
              </button>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/60 text-slate-400 uppercase font-mono text-[10px]">
                  <tr>
                    <th className="px-4 py-3">License ID</th>
                    <th className="px-4 py-3">Organization</th>
                    <th className="px-4 py-3">Plan</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Limits (Users/Devices/Scans)</th>
                    <th className="px-4 py-3">Expires At</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/40">
                  {licenses.map(l => (
                    <tr key={l.license_id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="px-4 py-3 font-mono text-indigo-400">{l.license_id}</td>
                      <td className="px-4 py-3 font-bold text-slate-200">{l.organization_name}</td>
                      <td className="px-4 py-3 text-slate-300">{l.plan_name}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          l.status === 'ACTIVE' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'
                        }`}>
                          {l.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-300 font-mono">
                        {l.max_users} / {l.max_devices} / {l.scan_limit === -1 ? 'Unlimited' : l.scan_limit}
                      </td>
                      <td className="px-4 py-3 text-slate-400">{new Date(l.expires_at).toLocaleDateString()}</td>
                      <td className="px-4 py-3 text-right space-x-1">
                        <button
                          onClick={() => handleExtendLicense(l.license_id)}
                          className="px-2 py-1 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-400 font-bold rounded border border-indigo-500/30"
                        >
                          Extend
                        </button>
                        {l.status === 'ACTIVE' ? (
                          <button
                            onClick={() => handleLicenseStatus(l.license_id, 'SUSPENDED')}
                            className="px-2 py-1 bg-amber-600/20 hover:bg-amber-600/30 text-amber-400 font-bold rounded border border-amber-500/30"
                          >
                            Suspend
                          </button>
                        ) : (
                          <button
                            onClick={() => handleLicenseStatus(l.license_id, 'ACTIVE')}
                            className="px-2 py-1 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 font-bold rounded border border-emerald-500/30"
                          >
                            Activate
                          </button>
                        )}
                        <button
                          onClick={() => handleLicenseStatus(l.license_id, 'REVOKED')}
                          className="px-2 py-1 bg-rose-600/20 hover:bg-rose-600/30 text-rose-400 font-bold rounded border border-rose-500/30"
                        >
                          Revoke
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Issue License Modal */}
            {showIssueModal && (
              <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                <form onSubmit={handleIssueLicense} className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
                  <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                    <KeyRound className="w-5 h-5 text-indigo-400" /> Issue Enterprise License
                  </h3>
                  <div>
                    <label className="text-xs text-slate-400 block mb-1">Organization ID</label>
                    <input
                      type="text"
                      required
                      placeholder="org-id..."
                      value={newLicenseOrgId}
                      onChange={e => setNewLicenseOrgId(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 font-mono"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-slate-400 block mb-1">Plan Tier</label>
                    <select
                      value={newLicensePlanId}
                      onChange={e => setNewLicensePlanId(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                    >
                      <option value="plan-starter-trial">Starter Trial</option>
                      <option value="plan-professional">Professional</option>
                      <option value="plan-enterprise">Enterprise Suite</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-xs text-slate-400 block mb-1">Duration (Days)</label>
                    <input
                      type="number"
                      value={newLicenseDays}
                      onChange={e => setNewLicenseDays(Number(e.target.value))}
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 font-mono"
                    />
                  </div>
                  <div className="flex justify-end gap-2 pt-2">
                    <button
                      type="button"
                      onClick={() => setShowIssueModal(false)}
                      className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold rounded-xl"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold rounded-xl"
                    >
                      Issue License
                    </button>
                  </div>
                </form>
              </div>
            )}
          </div>
        )}

        {/* SUBSCRIPTIONS TAB */}
        {activeSubTab === 'subscriptions' && (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
            <div className="px-5 py-4 border-b border-slate-800 text-xs font-bold text-slate-300 uppercase tracking-wider">
              Commercial Subscriptions & Billing State ({subscriptions.length})
            </div>
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 uppercase font-mono text-[10px]">
                <tr>
                  <th className="px-4 py-3">Subscription ID</th>
                  <th className="px-4 py-3">Organization</th>
                  <th className="px-4 py-3">Plan</th>
                  <th className="px-4 py-3">Billing Status</th>
                  <th className="px-4 py-3">Interval</th>
                  <th className="px-4 py-3">Current Period End</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40">
                {subscriptions.map(s => (
                  <tr key={s.subscription_id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3 font-mono text-indigo-400">{s.subscription_id}</td>
                    <td className="px-4 py-3 font-bold text-slate-200">{s.organization_name}</td>
                    <td className="px-4 py-3 text-slate-300">{s.plan_name}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        s.status === 'ACTIVE' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-amber-500/20 text-amber-300'
                      }`}>
                        {s.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-300">{s.billing_interval}</td>
                    <td className="px-4 py-3 text-slate-400">{new Date(s.current_period_end).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* USAGE & TELEMETRY TAB */}
        {activeSubTab === 'usage' && usage && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-xl">
                <div className="text-slate-500 text-xs">Total Organizations</div>
                <div className="text-2xl font-bold text-slate-100 mt-1">{usage.total_organizations}</div>
              </div>
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-xl">
                <div className="text-slate-500 text-xs">Total Registered Users</div>
                <div className="text-2xl font-bold text-slate-100 mt-1">{usage.total_users}</div>
              </div>
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-xl">
                <div className="text-slate-500 text-xs">Active Devices</div>
                <div className="text-2xl font-bold text-slate-100 mt-1">{usage.total_devices}</div>
              </div>
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-xl">
                <div className="text-slate-500 text-xs">Completed Scans</div>
                <div className="text-2xl font-bold text-slate-100 mt-1">{usage.total_scans}</div>
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <h3 className="text-sm font-bold text-slate-200">Aggregated Telemetry Volume</h3>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                  <div className="text-xs text-slate-500">Total Telemetry Records Logged</div>
                  <div className="text-lg font-bold text-indigo-400 mt-1">{usage.telemetry?.telemetry_records || 0}</div>
                </div>
                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                  <div className="text-xs text-slate-500">Total Files Discovered Across Fleet</div>
                  <div className="text-lg font-bold text-emerald-400 mt-1">{usage.telemetry?.total_files_discovered || 0}</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* SECURITY & AUDIT EVENTS TAB */}
        {activeSubTab === 'security' && (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
            <div className="px-5 py-4 border-b border-slate-800 text-xs font-bold text-slate-300 uppercase tracking-wider flex justify-between items-center">
              <span>Security Audit Events & Monitoring ({securityEvents.length})</span>
            </div>
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 uppercase font-mono text-[10px]">
                <tr>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Event Type</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Org ID</th>
                  <th className="px-4 py-3">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40 font-mono text-[11px]">
                {securityEvents.map(e => (
                  <tr key={e.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3 text-slate-400">{new Date(e.timestamp).toLocaleString()}</td>
                    <td className="px-4 py-3 font-bold text-indigo-300">{e.event_type}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] ${
                        e.status === 'SUCCESS' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'
                      }`}>
                        {e.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-400">{e.org_id || 'N/A'}</td>
                    <td className="px-4 py-3 text-slate-300 truncate max-w-xs">{e.details || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* SYSTEM & UPDATES TAB */}
        {activeSubTab === 'system' && systemInfo && (
          <div className="max-w-2xl space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                <div>
                  <h3 className="text-base font-bold text-slate-100">FileSentinel Core Engine System</h3>
                  <p className="text-xs text-slate-400">Current running build and update availability</p>
                </div>
                {systemInfo.update_available && (
                  <span className="px-3 py-1 bg-emerald-500/20 text-emerald-300 text-xs font-bold rounded-lg border border-emerald-500/30 animate-pulse">
                    Update Available
                  </span>
                )}
              </div>

              <div className="grid grid-cols-2 gap-4 text-xs">
                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                  <div className="text-slate-500">Current Application Version</div>
                  <div className="text-lg font-bold font-mono text-indigo-400 mt-1">{systemInfo.current_application_version}</div>
                </div>
                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                  <div className="text-slate-500">Latest Available Version</div>
                  <div className="text-lg font-bold font-mono text-emerald-400 mt-1">{systemInfo.latest_available_version}</div>
                </div>
              </div>

              <div className="space-y-2">
                <div className="text-xs font-bold text-slate-300">Supported Agent Versions</div>
                <div className="flex gap-2">
                  {systemInfo.agent_versions_supported.map((v: string) => (
                    <span key={v} className="px-2.5 py-1 bg-slate-800 text-slate-200 font-mono text-xs rounded-lg border border-slate-700">
                      v{v}
                    </span>
                  ))}
                </div>
              </div>

              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                <div className="text-xs font-bold text-slate-200">Release Notes ({systemInfo.latest_available_version})</div>
                <p className="text-xs text-slate-400">{systemInfo.update_release_notes}</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
