import fs from 'fs';
let content = fs.readFileSync('src/services/api.ts', 'utf8');
content = content.replace(
  "target_dir?: string;",
  "target_dir?: string;\n    scan_roots?: string[];"
);
fs.writeFileSync('src/services/api.ts', content);
