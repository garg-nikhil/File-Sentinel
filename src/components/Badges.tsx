import React from 'react';
import { Severity, Classification } from '../types';

export const SeverityBadge: React.FC<{ severity: Severity; className?: string }> = ({ severity, className = '' }) => {
  const styles: Record<Severity, string> = {
    CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
    HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
    MEDIUM: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    LOW: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    INFO: 'bg-blue-500/15 text-blue-400 border-blue-500/30'
  };

  return (
    <span id={`badge-sev-${severity.toLowerCase()}`} className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${styles[severity] || styles.INFO} ${className}`}>
      {severity}
    </span>
  );
};

export const ClassificationBadge: React.FC<{ classification: Classification }> = ({ classification }) => {
  const styles: Record<Classification, string> = {
    RESTRICTED: 'bg-purple-950/60 text-purple-300 border-purple-500/40',
    CONFIDENTIAL: 'bg-red-950/60 text-red-300 border-red-500/40',
    INTERNAL: 'bg-blue-950/60 text-blue-300 border-blue-500/40',
    PUBLIC: 'bg-emerald-950/60 text-emerald-300 border-emerald-500/40',
    UNKNOWN: 'bg-gray-800 text-gray-400 border-gray-700'
  };

  return (
    <span id={`badge-class-${classification.toLowerCase()}`} className={`inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-mono font-medium border ${styles[classification] || styles.UNKNOWN}`}>
      {classification}
    </span>
  );
};
