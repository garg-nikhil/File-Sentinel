import fs from 'fs';

let content = fs.readFileSync('src/components/audit/AuditComplianceView.tsx', 'utf8');

content = content.replace(
  "const [targetDir, setTargetDir] = useState<string>('');",
  "const [scanRoots, setScanRoots] = useState<string[]>(['']);"
);

content = content.replace(
  "if (!targetDir.trim() && !recentScanId) {",
  "if (scanRoots.filter(r => r.trim()).length === 0 && !recentScanId) {"
);

content = content.replace(
  "target_dir: targetDir.trim() || undefined,",
  "scan_roots: scanRoots.filter(r => r.trim()),"
);

content = content.replace(
  "disabled={scanning || (!targetDir.trim() && !recentScanId)}",
  "disabled={scanning || (scanRoots.filter(r => r.trim()).length === 0 && !recentScanId)}"
);

const oldInputSection = `          <div>
            <label className="block font-semibold text-slate-600 dark:text-slate-400 mb-1">Scan Target Directory</label>
            <input
              type="text"
              value={targetDir}
              onChange={e => setTargetDir(e.target.value)}
              placeholder="e.g. /path/to/evidence/folder"
              className="w-full p-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-slate-100 font-mono"
            />
          </div>`;

const newInputSection = `          <div className="col-span-1 md:col-span-2">
            <div className="flex justify-between items-center mb-1">
              <label className="block font-semibold text-slate-600 dark:text-slate-400">Scan Targets (Multi-Root)</label>
              <button 
                onClick={() => setScanRoots([...scanRoots, ''])}
                className="text-xs text-indigo-600 hover:text-indigo-800 dark:text-indigo-400 flex items-center gap-1 font-semibold"
              >
                + Add Folder
              </button>
            </div>
            <div className="space-y-2">
              {scanRoots.map((root, i) => (
                <div key={i} className="flex gap-2">
                  <input
                    type="text"
                    value={root}
                    onChange={e => {
                      const newRoots = [...scanRoots];
                      newRoots[i] = e.target.value;
                      setScanRoots(newRoots);
                    }}
                    placeholder="e.g. /path/to/evidence/folder"
                    className="flex-1 p-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-slate-100 font-mono text-sm"
                  />
                  {scanRoots.length > 1 && (
                    <button onClick={() => setScanRoots(scanRoots.filter((_, idx) => idx !== i))} className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg">
                      ✕
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>`;

content = content.replace(oldInputSection, newInputSection);

fs.writeFileSync('src/components/audit/AuditComplianceView.tsx', content);
