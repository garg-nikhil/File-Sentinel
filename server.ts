import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { createApiRouter } from './backend/routes.js';

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // Mount API Router
  app.use('/api', createApiRouter());

  // Mount Vite middleware in development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[FileSentinel] Local-First Security Server running on http://localhost:${PORT}`);
  });
}

startServer().catch(err => {
  console.error('Failed to start FileSentinel server:', err);
});
