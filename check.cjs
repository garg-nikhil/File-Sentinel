const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync('./filesentinel.db');
console.log(db.prepare("PRAGMA table_info(files)").all());
