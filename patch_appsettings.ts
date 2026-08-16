import fs from 'fs';

let content = fs.readFileSync('src/types.ts', 'utf8');
content = content.replace(
  "  aiEnabled: boolean;",
  "  aiEnabled: boolean;\n  aiPrivacyMode?: 'OFF' | 'REDACTED_SNIPPETS' | 'FULL_TEXT';"
);
fs.writeFileSync('src/types.ts', content);

let routesContent = fs.readFileSync('backend/routes.ts', 'utf8');
routesContent = routesContent.replace(
  "aiEnabled: true,",
  "aiEnabled: true,\n    aiPrivacyMode: 'OFF',"
);
fs.writeFileSync('backend/routes.ts', routesContent);
