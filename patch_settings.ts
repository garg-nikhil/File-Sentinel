import fs from 'fs';

let content = fs.readFileSync('src/components/SettingsView.tsx', 'utf8');

const oldAiEnabled = `          <div className="flex items-center justify-between">
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
          </div>`;

const newAiEnabled = `          <div className="flex items-center justify-between">
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

          {settings.aiEnabled && (
            <div className="flex items-center justify-between pl-4 border-l-2 border-slate-700">
              <div>
                <span className="text-sm font-semibold text-slate-200 block">AI Evidence Assistance Privacy Mode</span>
                <span className="text-xs text-slate-400">Controls how much evidence context is shared with the Gemini AI.</span>
              </div>
              <select
                value={settings.aiPrivacyMode || 'OFF'}
                onChange={e => setSettings({ ...settings, aiPrivacyMode: e.target.value as 'OFF' | 'REDACTED_SNIPPETS' | 'FULL_TEXT' })}
                className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded px-2 py-1 outline-none focus:border-indigo-500"
              >
                <option value="OFF">OFF (No context shared)</option>
                <option value="REDACTED_SNIPPETS">REDACTED SNIPPETS (Safe snippets only)</option>
                <option value="FULL_TEXT">FULL TEXT (Unredacted document content)</option>
              </select>
            </div>
          )}`;

content = content.replace(oldAiEnabled, newAiEnabled);

fs.writeFileSync('src/components/SettingsView.tsx', content);
