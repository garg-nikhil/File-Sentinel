import React, { useState, useEffect } from 'react';
import { FileItem, AISummary } from '../types';
import { api } from '../services/api';
import { SeverityBadge, ClassificationBadge } from './Badges';
import {
  ArrowLeft,
  Shield,
  ShieldAlert,
  CloudUpload,
  Copy,
  Check,
  Sparkles,
  AlertTriangle,
  FileText,
  Lock,
  Trash2,
  Terminal
} from 'lucide-react';

interface FileDetailViewProps {
  fileId: string;
  onBack: () => void;
}

export const FileDetailView: React.FC<FileDetailViewProps> = ({ fileId, onBack }) => {
  const [file, setFile] = useState<FileItem | null>(null);
  const [loading, setLoading] = useState(true);
  const [copiedSha, setCopiedSha] = useState(false);
  const [isAnalyzingAI, setIsAnalyzingAI] = useState(false);
  const [aiResult, setAiResult] = useState<AISummary | null>(null);
  const [quarantineMsg, setQuarantineMsg] = useState<string | null>(null);

  useEffect(() => {
    loadFileDetail();
  }, [fileId]);

  const loadFileDetail = async () => {
    try {
      setLoading(true);
      const data = await api.getFileDetail(fileId);
      setFile(data);
      if (data.ai_summary) {
        setAiResult(data.ai_summary);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleCopySha = () => {
    if (file) {
      navigator.clipboard.writeText(file.sha256);
      setCopiedSha(true);
      setTimeout(() => setCopiedSha(false), 2000);
    }
  };

  const handleAnalyzeAI = async () => {
    try {
      setIsAnalyzingAI(true);
      const res = await api.analyzeFileWithAI(fileId);
      if (res.ai_summary) {
        setAiResult(res.ai_summary);
        // Refresh file detail
        loadFileDetail();
      }
    } catch (err: any) {
      alert(err.message || 'AI semantic analysis unavailable.');
    } finally {
      setIsAnalyzingAI(false);
    }
  };

  const handleStageQuarantine = async () => {
    try {
      await api.quarantineFile(fileId);
      setQuarantineMsg('File staged into Quarantine Vault registry.');
      setTimeout(() => setQuarantineMsg(null), 3000);
    } catch (e: any) {
      alert(e.message || 'Failed to stage quarantine.');
    }
  };



  if (loading || !file) {
    return (
      <div className="p-12 text-center text-slate-400 font-mono animate-pulse">
        Loading file inspection details...
      </div>
    );
  }

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-8">
      {/* Top Back Navigation */}
      <div className="flex items-center justify-between">
        <button
          onClick={onBack}
          className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-slate-100 font-medium transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Scanned Index
        </button>

        <div className="flex items-center gap-3">
          <button
            onClick={handleStageQuarantine}
            className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors border border-slate-700 flex items-center gap-2"
          >
            <Lock className="w-3.5 h-3.5" />
            Stage Quarantine
          </button>
        </div>
      </div>

      {quarantineMsg && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs font-mono text-emerald-400">
          {quarantineMsg}
        </div>
      )}

      {/* Main File Header Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div>
            <div className="flex items-center gap-3 flex-wrap">
              <h2 className="text-xl font-bold font-mono text-slate-100">{file.filename}</h2>
              <ClassificationBadge classification={file.classification} />
            </div>
            <p className="text-xs font-mono text-slate-400 mt-1 break-all">{file.path}</p>
          </div>

          {/* Risk Gauge */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 shrink-0 text-center flex items-center gap-4">
            <div>
              <div className="text-3xl font-extrabold font-mono text-red-400">{file.risk_score}</div>
              <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Risk Score (0-100)</div>
            </div>
            <div className="w-px h-10 bg-slate-800"></div>
            <div className="text-left">
              <div className="text-xs text-slate-400">Findings Detected</div>
              <div className="text-sm font-bold text-slate-200 font-mono mt-0.5">{file.findings?.length || 0} issues</div>
            </div>
          </div>
        </div>

        {/* Metadata Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-4 border-t border-slate-800/80 text-xs font-mono">
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">SHA-256 Fingerprint</span>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-slate-300 truncate">{file.sha256}</span>
              <button onClick={handleCopySha} className="text-slate-400 hover:text-slate-100">
                {copiedSha ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          <div>
            <span className="text-slate-500 block text-[10px] uppercase">File Size</span>
            <span className="text-slate-300 mt-1 block">{(file.size / 1024).toFixed(2)} KB</span>
          </div>

          <div>
            <span className="text-slate-500 block text-[10px] uppercase">File Extension</span>
            <span className="text-slate-300 mt-1 block uppercase font-bold">{file.extension}</span>
          </div>

          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Scan Status</span>
            <span className="text-emerald-400 font-bold mt-1 block">{file.scan_status}</span>
          </div>
        </div>
      </div>



      {/* Gemini AI Semantic Analysis Section */}
      <div className="bg-slate-900 border border-purple-500/30 rounded-xl p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-purple-400" />
            <h3 className="text-base font-bold text-slate-100">Gemini AI Semantic Compliance & Risk Assessment</h3>
          </div>
          <button
            onClick={handleAnalyzeAI}
            disabled={isAnalyzingAI}
            className="px-3.5 py-1.5 bg-purple-600 hover:bg-purple-500 text-white text-xs font-medium rounded-lg transition-colors flex items-center gap-1.5 disabled:opacity-50"
          >
            <Sparkles className="w-3.5 h-3.5" />
            {isAnalyzingAI ? 'Analyzing...' : aiResult ? 'Re-Analyze AI' : 'Run Gemini Analysis'}
          </button>
        </div>

        {aiResult ? (
          <div className="bg-slate-950/80 border border-purple-500/20 rounded-lg p-4 space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-slate-400 font-semibold">AI Risk Level:</span>
                <SeverityBadge severity={aiResult.risk_level} />
                <span className="text-slate-400 font-semibold ml-3">AI Classification:</span>
                <ClassificationBadge classification={aiResult.classification} />
              </div>
              <span className="text-slate-500 font-mono">Confidence: {(aiResult.confidence * 100).toFixed(0)}%</span>
            </div>

            <div>
              <span className="text-slate-400 font-semibold block mb-1">Executive Summary:</span>
              <p className="text-slate-200 leading-relaxed">{aiResult.summary}</p>
            </div>

            <div>
              <span className="text-slate-400 font-semibold block mb-1">Reasoning & Risk Assessment:</span>
              <p className="text-slate-300 leading-relaxed">{aiResult.reasoning}</p>
            </div>

            <div className="pt-2 border-t border-slate-800">
              <span className="text-emerald-400 font-semibold block mb-1">Recommended Remediation:</span>
              <p className="text-slate-300 font-mono bg-slate-900 p-2 rounded border border-slate-800">{aiResult.recommended_action}</p>
            </div>
          </div>
        ) : (
          <p className="text-xs text-slate-400 italic">
            Click "Run Gemini Analysis" to send extracted text to Gemini for semantic classification, compliance summary, and risk assessment.
          </p>
        )}
      </div>

      {/* DLP Findings List */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-amber-400" />
          Detected DLP Findings & Rule Triggers ({file.findings?.length || 0})
        </h3>

        {!file.findings || file.findings.length === 0 ? (
          <p className="text-xs text-slate-500 italic py-4">No DLP security findings detected in this file.</p>
        ) : (
          <div className="space-y-3">
            {file.findings.map(finding => (
              <div key={finding.finding_id} className="bg-slate-950 border border-slate-800 p-4 rounded-lg space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={finding.severity} />
                    <span className="text-sm font-bold text-slate-200">{finding.title}</span>
                    <span className="text-xs font-mono text-slate-500">[{finding.rule_id}]</span>
                  </div>
                  <span className="text-[10px] font-mono bg-slate-900 text-slate-400 px-2 py-0.5 rounded border border-slate-800">
                    Category: {finding.category}
                  </span>
                </div>

                <p className="text-xs text-slate-300">{finding.description}</p>

                {finding.evidence?.snippet && (
                  <div className="bg-slate-900 p-2.5 rounded border border-slate-800 font-mono text-xs text-amber-300/90 break-all">
                    <span className="text-slate-500 text-[10px] block uppercase font-sans mb-1">Evidence Match Snippet</span>
                    {finding.evidence.snippet}
                  </div>
                )}

                <div className="text-xs text-emerald-400 font-medium pt-1">
                  Recommendation: {finding.recommendation}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Extracted Content Safe Preview */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-3">
        <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
          <FileText className="w-4 h-4 text-slate-400" />
          Safe Extracted Content Text Preview
        </h3>
        <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 font-mono text-xs text-slate-300 max-h-60 overflow-y-auto whitespace-pre-wrap">
          {file.extracted_text_preview || 'No extractable plain text content found.'}
        </div>
      </div>
    </div>
  );
};
