import fs from 'fs';
let content = fs.readFileSync('backend/routes.ts', 'utf8');
content = content.replace(
  `        const targetDir = path.resolve(target_dir.trim());
        if (!fs.existsSync(targetDir)) {
          return res.status(400).json({ error: \`Directory target does not exist: \${targetDir}\` });
        }`,
  `        const validRoots = roots.map((r: string) => path.resolve(r.trim())).filter((r: string) => fs.existsSync(r));
        if (validRoots.length === 0) {
          return res.status(400).json({ error: 'None of the provided directory targets exist.' });
        }`
);
content = content.replace(
  "logAuditEvent('RUN_AUDIT_COMPLIANCE', targetDir, undefined, 'SUCCESS', `Audit ID: ${session.audit_id}, Score: ${session.overall_score}`);",
  "logAuditEvent('RUN_AUDIT_COMPLIANCE', validRoots.join(', '), undefined, 'SUCCESS', `Audit ID: ${session.audit_id}, Score: ${session.overall_score}`);"
);
fs.writeFileSync('backend/routes.ts', content);
