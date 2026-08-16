const fs = require('fs');

let content = fs.readFileSync('backend/scannerEngine.ts', 'utf-8');

// First replacement (SKIPPED files)
content = content.replace(
  /extracted_text_preview, metadata_json, warnings_json\s*\)\s*VALUES\s*\(\?,\s*\?,\s*\?,\s*\?,\s*\?,\s*\?,\s*\?,\s*0,\s*'UNKNOWN',\s*'SKIPPED',\s*\?,\s*\?,\s*'',\s*\?,\s*\?\)/,
  "extracted_text_preview, extracted_text, metadata_json, warnings_json\n              ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'UNKNOWN', 'SKIPPED', ?, ?, '', '', ?, ?)"
);

// Second replacement (Processed files)
content = content.replace(
  /extracted_text_preview, metadata_json, warnings_json\s*\)\s*VALUES\s*\(\?,\s*\?,\s*\?,\s*\?,\s*\?,\s*\?,\s*\?,\s*\?,\s*\?,\s*\?,\s*\?,\s*\?,\s*\?,\s*\?,\s*\?\)/,
  "extracted_text_preview, extracted_text, metadata_json, warnings_json\n            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
);

// Third replacement (adding text parameter)
content = content.replace(
  /text\.substring\(0,\s*500\),\s*JSON\.stringify\(metadata\),\s*JSON\.stringify\(warnings\)\s*\);/,
  "text.substring(0, 500),\n            text,\n            JSON.stringify(metadata),\n            JSON.stringify(warnings)\n          );"
);

fs.writeFileSync('backend/scannerEngine.ts', content, 'utf-8');
