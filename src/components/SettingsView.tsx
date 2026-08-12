import React, { useState, useEffect } from 'react';
import { AppSettings } from '../types';
import { api } from '../services/api';
import { Settings, Save, RefreshCw, CheckCircle2, Shield } from 'lucide-react';

export const SettingsView: React.FC = () => {
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [savedMsg, setSavedMsg] = useState(false);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      const data = await api.getSettings();
      setSettings(data);
    } catch (e) {
      console.error(e);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!settings) return;

    try {
      setSaving(true);
      await api.updateSettings(settings);
      setSavedMsg(true);
      setTimeout(() => setSavedMsg(false), 3000);
    } catch (e) {
      console.error(e);
    } finally {
      setSaving(false);
    }
  };

  if (!settings) {
    return <div className="p-8 text-center text-slate-400 font-mono animate-pulse">Loading app settings...</div>;
  }

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-8">
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Settings className="w-5 h-5 text-emerald-400" />
          FileSentinel Configuration & Privacy Settings
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Configure static analysis boundaries, AI assistance parameters, and storage vault preferences.
        </p>
      </div>

      <form onSubmit={handleSave} className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase mb-2">
              Max File Size Limit (MB)
            </label>
            <input
              type="number"
              value={settings.maxFileSizeMB}
              onChange={e => setSettings({ ...settings, maxFileSizeMB: parseInt(e.target.value) || 10 })}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-sm font-mono text-slate-100 focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase mb-2">
              Max Directory Recursive Depth
            </label>
            <input
              type="number"
              value={settings.maxScanDepth}
              onChange={e => setSettings({ ...settings, maxScanDepth: parseInt(e.target.value) || 5 })}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-sm font-mono text-slate-100 focus:outline-none focus:border-emerald-500"
            />
          </div>
        </div>

        <div className="space-y-4 pt-4 border-t border-slate-800/80">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-sm font-semibold text-slate-200 block">Gemini AI Semantic Evaluation</span>
              <span className="text-xs text-slate-400">Allow server-side Gemini 3.6 Flash calls for document risk classification and summaries.</span>
            </div>
            <input
              type="checkbox"
              checked={settings.aiEnabled}
              onChange={e => setSettings({ ...settings, aiEnabled: e.target.checked })}
              className="w-4 h-4 accent-emerald-500 rounded cursor-pointer"
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <span className="text-sm font-semibold text-slate-200 block">Cloud Quarantine & Verified Removal</span>
              <span className="text-xs text-slate-400">Enable cloud storage staging and verified local deletion workflow.</span>
            </div>
            <input
              type="checkbox"
              checked={settings.cloudUploadEnabled}
              onChange={e => setSettings({ ...settings, cloudUploadEnabled: e.target.checked })}
              className="w-4 h-4 accent-emerald-500 rounded cursor-pointer"
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <span className="text-sm font-semibold text-slate-200 block">Mask Sensitive Preview Snippets</span>
              <span className="text-xs text-slate-400">Redact matched credential keys and PII in evidence previews.</span>
            </div>
            <input
              type="checkbox"
              checked={settings.redactSensitivePreview}
              onChange={e => setSettings({ ...settings, redactSensitivePreview: e.target.checked })}
              className="w-4 h-4 accent-emerald-500 rounded cursor-pointer"
            />
          </div>
        </div>

        <div className="flex items-center justify-between pt-4 border-t border-slate-800/80">
          {savedMsg && (
            <span className="text-xs text-emerald-400 font-mono flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4" />
              Settings updated successfully
            </span>
          )}
          <button
            type="submit"
            disabled={saving}
            className="ml-auto bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-5 py-2.5 rounded-lg text-xs flex items-center gap-2 transition-colors"
          >
            <Save className="w-4 h-4" />
            {saving ? 'Saving...' : 'Save Settings'}
          </button>
        </div>
      </form>
    </div>
  );
};
