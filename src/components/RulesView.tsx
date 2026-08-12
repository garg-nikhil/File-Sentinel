import React, { useState, useEffect } from 'react';
import { Rule, Severity, Category } from '../types';
import { api } from '../services/api';
import { SeverityBadge } from './Badges';
import { SlidersHorizontal, Plus, Power, Check } from 'lucide-react';

export const RulesView: React.FC = () => {
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);

  // New Rule Form
  const [name, setName] = useState('');
  const [category, setCategory] = useState<Category>('SECRETS');
  const [severity, setSeverity] = useState<Severity>('HIGH');
  const [pattern, setPattern] = useState('');
  const [description, setDescription] = useState('');
  const [recommendation, setRecommendation] = useState('');

  useEffect(() => {
    loadRules();
  }, []);

  const loadRules = async () => {
    try {
      setLoading(true);
      const data = await api.getRules();
      setRules(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleToggle = async (ruleId: string, currentStatus: boolean) => {
    try {
      await api.toggleRule(ruleId, !currentStatus);
      setRules(prev =>
        prev.map(r => (r.id === ruleId ? { ...r, enabled: !currentStatus } : r))
      );
    } catch (e) {
      console.error(e);
    }
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name || !pattern) return;

    try {
      await api.createRule({
        name,
        category,
        severity,
        enabled: true,
        pattern,
        description,
        recommendation
      });
      setShowAddModal(false);
      setName('');
      setPattern('');
      setDescription('');
      setRecommendation('');
      loadRules();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <SlidersHorizontal className="w-5 h-5 text-emerald-400" />
            Configurable DLP Rule Engine
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Enable, disable, or author regular expression security rules evaluated during static scans.
          </p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded-lg transition-colors flex items-center gap-2"
        >
          <Plus className="w-4 h-4" />
          Add Custom Rule
        </button>
      </div>

      {/* Rules Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {loading ? (
          <div className="col-span-2 p-12 text-center text-slate-400 font-mono animate-pulse">
            Loading rule definitions...
          </div>
        ) : (
          rules.map(rule => (
            <div
              key={rule.id}
              className={`bg-slate-900 border p-5 rounded-xl space-y-3 transition-colors ${
                rule.enabled ? 'border-slate-800' : 'border-slate-800/40 opacity-60'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={rule.severity} />
                  <span className="text-xs font-mono font-bold text-slate-400">[{rule.id}]</span>
                  <span className="text-xs font-mono bg-slate-950 px-2 py-0.5 rounded text-slate-400 border border-slate-800">
                    {rule.category}
                  </span>
                </div>

                <button
                  onClick={() => handleToggle(rule.id, rule.enabled)}
                  className={`px-2.5 py-1 rounded text-xs font-mono font-bold flex items-center gap-1.5 border transition-colors ${
                    rule.enabled
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                      : 'bg-slate-800 text-slate-400 border-slate-700 hover:bg-slate-700'
                  }`}
                >
                  <Power className="w-3 h-3" />
                  {rule.enabled ? 'ENABLED' : 'DISABLED'}
                </button>
              </div>

              <div>
                <h3 className="text-sm font-bold text-slate-100">{rule.name}</h3>
                <p className="text-xs text-slate-400 mt-0.5">{rule.description}</p>
              </div>

              <div className="bg-slate-950 p-2.5 rounded font-mono text-xs text-slate-300 break-all border border-slate-800/80">
                <span className="text-slate-500 text-[10px] block font-sans mb-1 uppercase">Regex Pattern</span>
                {rule.pattern}
              </div>

              <div className="text-[11px] text-slate-400 italic">
                Recommendation: {rule.recommendation}
              </div>
            </div>
          ))
        )}
      </div>

      {/* Add Custom Rule Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-4">
            <h3 className="text-base font-bold text-slate-100">Author Custom Security Rule</h3>
            <form onSubmit={handleCreateRule} className="space-y-4 text-xs font-sans">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Rule Name</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={e => setName(e.target.value)}
                  placeholder="e.g. Internal Secret Code"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-100"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Category</label>
                  <select
                    value={category}
                    onChange={e => setCategory(e.target.value as Category)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-100"
                  >
                    <option value="SECRETS">SECRETS</option>
                    <option value="PII">PII</option>
                    <option value="FINANCIAL">FINANCIAL</option>
                    <option value="SECURITY">SECURITY</option>
                    <option value="DOCUMENT">DOCUMENT</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Severity</label>
                  <select
                    value={severity}
                    onChange={e => setSeverity(e.target.value as Severity)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-100"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Regex Pattern</label>
                <input
                  type="text"
                  required
                  value={pattern}
                  onChange={e => setPattern(e.target.value)}
                  placeholder="e.g. (?i)secret_token_\d+"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 font-mono text-slate-100"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Description</label>
                <textarea
                  value={description}
                  onChange={e => setDescription(e.target.value)}
                  placeholder="Brief description of risk..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-100"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Recommendation</label>
                <input
                  type="text"
                  value={recommendation}
                  onChange={e => setRecommendation(e.target.value)}
                  placeholder="Remediation recommendation..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-100"
                />
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 bg-slate-800 text-slate-300 rounded-lg font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-semibold"
                >
                  Save Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
