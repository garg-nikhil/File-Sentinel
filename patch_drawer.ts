import fs from 'fs';

let content = fs.readFileSync('src/components/audit/AuditDetailDrawer.tsx', 'utf8');

const oldEvidenceSection = `          {/* Matched Evidence Files */}
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
          </div>`;

const newEvidenceSection = `          {/* Matched Evidence Files */}
          <div className="mt-6">
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 mb-3 flex items-center gap-2">
              <FileText className="w-4 h-4 text-indigo-500" />
              Evidence Set ({parameterResult.evidence.length})
            </h3>
            {parameterResult.evidence.length === 0 ? (
              <div className="p-6 text-center border-2 border-dashed border-slate-200 dark:border-slate-800 rounded-xl text-slate-400 text-xs">
                No matching evidence documents were discovered for this parameter in the scanned directory.
              </div>
            ) : (
              <div className="space-y-4">
                {parameterResult.evidence_set?.primaryEvidence && (
                  <div>
                    <div className="text-xs font-bold text-indigo-600 dark:text-indigo-400 mb-2 uppercase tracking-wider">Primary Evidence</div>
                    <EvidenceCard ev={parameterResult.evidence_set.primaryEvidence} tag="VALIDATED" color="bg-emerald-50 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300" />
                  </div>
                )}
                
                {parameterResult.evidence_set?.supportingEvidence?.length > 0 && (
                  <div>
                    <div className="text-xs font-bold text-slate-500 dark:text-slate-400 mb-2 uppercase tracking-wider">Supporting Evidence</div>
                    <div className="space-y-2">
                      {parameterResult.evidence_set.supportingEvidence.map((ev: any, idx: number) => (
                        <EvidenceCard key={idx} ev={ev} tag="VALIDATED" color="bg-indigo-50 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300" />
                      ))}
                    </div>
                  </div>
                )}

                {parameterResult.evidence_set?.reviewEvidence?.length > 0 && (
                  <div>
                    <div className="text-xs font-bold text-amber-600 dark:text-amber-500 mb-2 uppercase tracking-wider">Partial / Review Evidence</div>
                    <div className="space-y-2">
                      {parameterResult.evidence_set.reviewEvidence.map((ev: any, idx: number) => (
                        <EvidenceCard key={idx} ev={ev} tag="REVIEW" color="bg-amber-50 text-amber-700 dark:bg-amber-950 dark:text-amber-300" />
                      ))}
                    </div>
                  </div>
                )}

                {parameterResult.evidence_set?.contradictoryEvidence?.length > 0 && (
                  <div>
                    <div className="text-xs font-bold text-rose-600 dark:text-rose-500 mb-2 uppercase tracking-wider">Contradictory Evidence</div>
                    <div className="space-y-2">
                      {parameterResult.evidence_set.contradictoryEvidence.map((ev: any, idx: number) => (
                        <EvidenceCard key={idx} ev={ev} tag="CONTRADICTORY" color="bg-rose-50 text-rose-700 dark:bg-rose-950 dark:text-rose-300" />
                      ))}
                    </div>
                  </div>
                )}

                {/* Fallback for legacy data */}
                {!parameterResult.evidence_set && (
                  <div className="space-y-2">
                    {parameterResult.evidence.map((ev: any, idx: number) => (
                      <EvidenceCard key={idx} ev={ev} tag="LEGACY" color="bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300" />
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>`;

content = content.replace(oldEvidenceSection, newEvidenceSection);

const evidenceCardComponent = `
function EvidenceCard({ ev, tag, color }: { ev: any, tag: string, color: string }) {
  return (
    <div className="p-3.5 bg-slate-50 dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 rounded-xl text-xs space-y-2">
      <div className="flex items-center justify-between">
        <span className="font-bold text-slate-900 dark:text-slate-100 truncate max-w-xs">{ev.filename}</span>
        <span className={\`px-2 py-0.5 font-semibold rounded text-[11px] \${color}\`}>
          {ev.classification || tag}
        </span>
      </div>
      {ev.validation_reason && (
         <div className="text-[11px] text-slate-500 dark:text-slate-400 mb-1">{ev.validation_reason}</div>
      )}
      <div className="p-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded text-slate-600 dark:text-slate-400 font-mono text-[11px] overflow-x-auto">
        {ev.snippet}
      </div>
      {ev.path && (
         <div className="text-[10px] text-slate-400 dark:text-slate-500 truncate" title={ev.path}>Location: {ev.path}</div>
      )}
      {ev.extracted_fields && Object.keys(ev.extracted_fields).length > 0 && (
        <div className="grid grid-cols-2 gap-2 text-[11px] pt-1 text-slate-500 dark:text-slate-400">
          {ev.extracted_fields.person_name && <div>Entity: <strong className="text-slate-800 dark:text-slate-200">{ev.extracted_fields.person_name}</strong></div>}
          {ev.extracted_fields.issue_date && <div>Issue Date: <strong className="text-slate-800 dark:text-slate-200">{ev.extracted_fields.issue_date}</strong></div>}
          {ev.extracted_fields.expiry_date && <div>Expiry Date: <strong className="text-slate-800 dark:text-slate-200">{ev.extracted_fields.expiry_date}</strong></div>}
          {ev.extracted_fields.gstin && <div>GSTIN: <strong className="text-slate-800 dark:text-slate-200">{ev.extracted_fields.gstin}</strong></div>}
          {ev.extracted_fields.policy_number && <div>Policy #: <strong className="text-slate-800 dark:text-slate-200">{ev.extracted_fields.policy_number}</strong></div>}
        </div>
      )}
    </div>
  );
}
`;

content = content.replace("export function AuditDetailDrawer", evidenceCardComponent + "\nexport function AuditDetailDrawer");

fs.writeFileSync('src/components/audit/AuditDetailDrawer.tsx', content);
