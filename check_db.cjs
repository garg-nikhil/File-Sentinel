const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync('./filesentinel.db');
const result = db.prepare("PRAGMA table_info(files);").all();
console.log(result.find(c => c.name === 'extracted_text') ? 'Has extracted_text' : 'Missing extracted_text');
