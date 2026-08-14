import React, { useState } from 'react';
import { X, CheckCircle2, AlertTriangle, XCircle, HelpCircle, FileText, Bot, Shield, UserCheck, Calendar, Clock, Lock } from 'lucide-react';
import { api } from '../../services/api';

interface AuditDetailDrawerProps {
  parameterResult: any;
  auditId: string;
  onClose: () => void;
  onOverrideSuccess: () => void;
}

export const AuditDetailDrawer: React.FC<AuditDetailDrawerProps> = ({
  parameterResult,
  auditId,
  onClose,
  onOverrideSuccess
}) => {
  const param = parameterResult.parameter;
  const currentStatus = parameterResult.override ? parameterResult.override.new_status : parameterResult.status;

  const [newStatus, setNewStatus] = useState<string>(currentStatus);
  const [auditorName, setAuditorName] = useState<string>(parameterResult.override?.auditor_name || 'Auditor Admin');
  const [comment, setComment] = useState<string>(parameterResult.override?.comment || '');
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [overrideSuccess, setOverrideSuccess] = useState<boolean>(false);

  const handleOverrideSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!auditorName.trim() || !comment.trim()) {
      alert('Please provide your Auditor Name and a justification comment.');
      return;
    }

    setSubmitting(true);
    try {
      await api.submitAuditorOverride({
        audit_id: auditId,
        parameter_id: parameterResult.parameter_id,
        new_status: newStatus,
        auditor_name: auditorName,
        comment
      });
      setOverrideSuccess(true);
      setTimeout(() => {
        onOverrideSuccess();
      }, 1000);
    } catch (err: any) {
      alert(`Override failed: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const renderStatusBadge = (st: string) => {
    switch (st) {
      case 'PASS':
        return <span className="px-3 py-1 bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 text-xs font-bold rounded-full inline-flex items-center gap-1.5 border border-emerald-300 dark:border-emerald-800"><CheckCircle2 className="w-3.5 h-3.5" /> PASS</span>;
      case 'FAIL':
        return <span className="px-3 py-1 bg-rose-100 dark:bg-rose-950/60 text-rose-700 dark:text-rose-400 text-xs font-bold rounded-full inline-flex items-center gap-1.5 border border-rose-300 dark:border-rose-800"><XCircle className="w-3.5 h-3.5" /> FAIL</span>;
      case 'REVIEW':
        return <span className="px-3 py-1 bg-amber-100 dark:bg-amber-950/60 text-amber-700 dark:text-amber-400 text-xs font-bold rounded-full inline-flex items-center gap-1.5 border border-amber-300 dark:border-amber-800"><AlertTriangle className="w-3.5 h-3.5" /> REVIEW REQUIRED</span>;
      case 'EVIDENCE_NOT_FOUND':
        return <span className="px-3 py-1 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 text-xs font-bold rounded-full inline-flex items-center gap-1.5 border border-slate-300 dark:border-slate-700"><HelpCircle className="w-3.5 h-3.5" /> EVIDENCE NOT FOUND</span>;
      default:
        return <span className="px-3 py-1 bg-slate-100 text-slate-700 text-xs font-bold rounded-full">{st}</span>;
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex justify-end transition-opacity">
      <div className="w-full max-w-2xl bg-white dark:bg-slate-900 h-full overflow-y-auto shadow-2xl border-l border-slate-200 dark:border-slate-800 p-6 flex flex-col justify-between">
        <div>
          {/* Header */}
          <div className="flex items-start justify-between pb-4 border-b border-slate-200 dark:border-slate-800">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">{param.category_name}</span>
                {parameterResult.fatal && (
                  <span className="px-2 py-0.5 bg-rose-100 text-rose-800 dark:bg-rose-900/60 dark:text-rose-300 text-[10px] font-extrabold uppercase rounded border border-rose-300 dark:border-rose-800">
                    🔴 FATAL REQUIREMENT
                  </span>
                )}
              </div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-slate-100">{parameterResult.parameter_id}: {param.parameter}</h2>
            </div>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Current Evaluation Box */}
          <div className="mt-5 p-4 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Evaluation Status</span>
              {renderStatusBadge(currentStatus)}
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs pt-1">
              <div>
                <span className="text-slate-500">Points Earned: </span>
                <strong className="text-slate-900 dark:text-slate-100">{parameterResult.score_earned} / {parameterResult.max_score} pts</strong>
              </div>
              <div>
                <span className="text-slate-500">Evaluation Confidence: </span>
                <strong className="text-slate-900 dark:text-slate-100">{Math.round((parameterResult.confidence || 0) * 100)}%</strong>
              </div>
            </div>

            {parameterResult.policy_status && (
              <div className="text-xs p-2.5 bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/60 rounded-lg text-amber-900 dark:text-amber-300">
                <strong>Policy vs Implementation:</strong> {parameterResult.policy_status.replace(/_/g, ' ')}
              </div>
            )}

            <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed font-medium">
              {parameterResult.reason}
            </p>

            {parameterResult.missing_requirements && parameterResult.missing_requirements.length > 0 && (
              <div className="p-3 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900 rounded-lg text-xs">
                <span className="font-bold text-rose-900 dark:text-rose-300">Missing Evidence Requirements:</span>
                <ul className="list-disc list-inside mt-1 space-y-0.5 text-rose-800 dark:text-rose-400">
                  {parameterResult.missing_requirements.map((req: string, i: number) => (
                    <li key={i}>{req}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Sub-Control / Compound Requirement Breakdown */}
          {parameterResult.sub_control_results && parameterResult.sub_control_results.length > 0 && (
            <div className="mt-5 space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  Sub-Control Validation Breakdown ({param.logic || 'AND'} Logic)
                </h3>
                <span className="text-[11px] font-semibold text-slate-500">
                  {parameterResult.sub_control_results.filter((s: any) => s.status === 'PASS').length} of {parameterResult.sub_control_results.length} Satisfied
                </span>
              </div>
              <div className="space-y-2">
                {parameterResult.sub_control_results.map((sub: any, sidx: number) => (
                  <div
                    key={sidx}
                    className="p-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl space-y-1.5 shadow-sm"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-xs text-slate-900 dark:text-slate-100">
                        {sub.name}
                      </span>
                      {renderStatusBadge(sub.status)}
                    </div>
                    <p className="text-[11px] text-slate-600 dark:text-slate-400">
                      {sub.reason || sub.description}
                    </p>
                    {sub.evidence && sub.evidence.length > 0 && (
                      <div className="text-[10px] text-slate-500 font-mono">
                        Evidence: {sub.evidence.map((e: any) => e.filename).join(', ')}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Auditor Override History Banner if Overridden */}
          {parameterResult.override && (
            <div className="mt-4 p-3 bg-cyan-50 dark:bg-cyan-950/40 border border-cyan-200 dark:border-cyan-800/60 rounded-xl text-xs space-y-1">
              <div className="flex items-center gap-1.5 text-cyan-900 dark:text-cyan-300 font-bold">
                <UserCheck className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                Auditor Manual Override Applied
              </div>
              <div className="text-slate-600 dark:text-slate-400">
                Auditor: <strong>{parameterResult.override.auditor_name}</strong> • Timestamp: {new Date(parameterResult.override.timestamp).toLocaleString()}
              </div>
              <div className="text-slate-700 dark:text-slate-300 italic">
                "{parameterResult.override.comment}"
              </div>
            </div>
          )}

          {/* Matched Evidence Files */}
          <div className="mt-6">
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 mb-3 flex items-center gap-2">
              <FileText className="w-4 h-4 text-indigo-500" />
              Matched Documentary Evidence ({parameterResult.evidence.length})
            </h3>

            {parameterResult.evidence.length === 0 ? (
              <div className="p-6 text-center border-2 border-dashed border-slate-200 dark:border-slate-800 rounded-xl text-slate-400 text-xs">
                No matching evidence documents were discovered for this parameter in the scanned directory.
              </div>
            ) : (
              <div className="space-y-3">
                {parameterResult.evidence.map((ev: any, idx: number) => (
                  <div key={idx} className="p-3.5 bg-slate-50 dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 rounded-xl text-xs space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-900 dark:text-slate-100 truncate max-w-xs">{ev.filename}</span>
                      <span className="px-2 py-0.5 bg-indigo-50 dark:bg-indigo-950 text-indigo-700 dark:text-indigo-300 font-semibold rounded text-[11px]">
                        Relevance: {Math.round(ev.relevance * 100)}%
                      </span>
                    </div>

                    <div className="p-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded text-slate-600 dark:text-slate-400 font-mono text-[11px] overflow-x-auto">
                      {ev.snippet}
                    </div>

                    {ev.extracted_fields && Object.keys(ev.extracted_fields).length > 0 && (
                      <div className="grid grid-cols-2 gap-2 text-[11px] pt-1 text-slate-500 dark:text-slate-400">
                        {ev.extracted_fields.person_name && <div>Person / Agent: <strong className="text-slate-800 dark:text-slate-200">{ev.extracted_fields.person_name}</strong></div>}
                        {ev.extracted_fields.issue_date && <div>Issue Date: <strong className="text-slate-800 dark:text-slate-200">{ev.extracted_fields.issue_date}</strong></div>}
                        {ev.extracted_fields.expiry_date && <div>Expiry Date: <strong className="text-slate-800 dark:text-slate-200">{ev.extracted_fields.expiry_date}</strong></div>}
                        {ev.extracted_fields.gstin && <div>GSTIN: <strong className="text-slate-800 dark:text-slate-200">{ev.extracted_fields.gstin}</strong></div>}
                        {ev.extracted_fields.policy_number && <div>Policy #: <strong className="text-slate-800 dark:text-slate-200">{ev.extracted_fields.policy_number}</strong></div>}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* AI Assistance Box */}
          {parameterResult.ai_recommendation && (
            <div className="mt-6 p-4 rounded-xl bg-indigo-50/70 dark:bg-indigo-950/40 border border-indigo-200 dark:border-indigo-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-indigo-900 dark:text-indigo-300 flex items-center gap-1.5">
                  <Bot className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                  Gemini AI Semantic Recommendation
                </span>
                <span className="text-[11px] font-semibold text-indigo-700 dark:text-indigo-300">
                  Confidence: {Math.round((parameterResult.ai_recommendation.confidence || 0) * 100)}%
                </span>
              </div>
              <p className="text-xs text-indigo-950 dark:text-indigo-200">
                {parameterResult.ai_recommendation.reason}
              </p>
              <div className="text-[11px] text-indigo-700 dark:text-indigo-400 italic">
                AI Recommendation: <strong>{parameterResult.ai_recommendation.recommended_status}</strong> (Note: Score calculation remains 100% deterministic)
              </div>
            </div>
          )}

          {/* Form for Auditor Override */}
          <div className="mt-8 pt-6 border-t border-slate-200 dark:border-slate-800">
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 mb-3 flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-600" />
              Auditor Manual Override Controls
            </h3>

            {overrideSuccess ? (
              <div className="p-3 bg-emerald-100 text-emerald-800 dark:bg-emerald-900/60 dark:text-emerald-200 rounded-xl text-xs font-bold text-center">
                ✅ Auditor override saved successfully. Scores updated!
              </div>
            ) : (
              <form onSubmit={handleOverrideSubmit} className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">New Status</label>
                    <select
                      value={newStatus}
                      onChange={e => setNewStatus(e.target.value)}
                      className="w-full text-xs p-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100"
                    >
                      <option value="PASS">PASS</option>
                      <option value="FAIL">FAIL</option>
                      <option value="REVIEW">REVIEW</option>
                      <option value="NOT_APPLICABLE">NOT APPLICABLE</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Auditor Name</label>
                    <input
                      type="text"
                      value={auditorName}
                      onChange={e => setAuditorName(e.target.value)}
                      placeholder="e.g. Lead Auditor Jane"
                      className="w-full text-xs p-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Justification / Audit Comment</label>
                  <textarea
                    value={comment}
                    onChange={e => setComment(e.target.value)}
                    rows={2}
                    placeholder="Describe why this result was overridden..."
                    className="w-full text-xs p-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100"
                  />
                </div>

                <button
                  type="submit"
                  disabled={submitting}
                  className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-bold text-xs rounded-lg transition-colors shadow disabled:opacity-50"
                >
                  {submitting ? 'Applying Override...' : 'Apply Auditor Override & Recalculate Scores'}
                </button>
              </form>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
