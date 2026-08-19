import fs from 'fs';

let content = fs.readFileSync('backend/routes.ts', 'utf8');

content = content.replace(
  "const { target_dir, scan_id, audit_date, agency_name, auditor_name } = req.body;",
  "const { target_dir, scan_roots, scan_id, audit_date, agency_name, auditor_name } = req.body;"
);

content = content.replace(
  "if (!target_dir || typeof target_dir !== 'string' || !target_dir.trim()) {",
  "const roots = scan_roots || (target_dir ? [target_dir] : []);\n        if (!roots || roots.length === 0 || roots.every((r: string) => !r.trim())) {"
);

content = content.replace(
  "return res.status(400).json({ error: 'Please specify a target directory path or scan ID for audit evaluation.' });",
  "return res.status(400).json({ error: 'Please specify at least one target directory path or scan ID for audit evaluation.' });"
);

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
  `        // Collect file paths
        const filePaths: string[] = [];
        function collectFiles(dir: string) {
          const entries = fs.readdirSync(dir, { withFileTypes: true });
          for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) collectFiles(fullPath);
            else filePaths.push(fullPath);
          }
        }
        collectFiles(targetDir);

        session = await evidenceEngine.runAuditScan(
          filePaths,`,
  `        // Collect file paths
        const filePaths: string[] = [];
        function collectFiles(dir: string) {
          const entries = fs.readdirSync(dir, { withFileTypes: true });
          for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) collectFiles(fullPath);
            else filePaths.push(fullPath);
          }
        }
        for (const root of validRoots) {
          collectFiles(root);
        }

        session = await evidenceEngine.runAuditScan(
          filePaths,`
);

fs.writeFileSync('backend/routes.ts', content);
