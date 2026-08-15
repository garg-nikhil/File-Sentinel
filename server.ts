import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { createApiRouter } from './backend/routes.js';
import { securityHeaders, corsMiddleware, enforceContentType, rateLimiter, safeErrorHandler } from './backend/securityMiddleware.js';

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Security Middleware
  app.use(securityHeaders);
  app.use(corsMiddleware);
  app.use(express.json({ limit: '100kb' }));
  app.use(enforceContentType);

  // Rate limiters for sensitive endpoints
  const apiRateLimiter = rateLimiter({ windowMs: 60000, max: 120 });
  app.use('/api', apiRateLimiter);

  // Mount API Router
  app.use('/api', createApiRouter());

  // Global Safe Error Handler
  app.use('/api', safeErrorHandler);

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

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`[FileSentinel] Local-First Security Server running on http://localhost:${PORT}`);
  });

  server.headersTimeout = 60000;
  server.requestTimeout = 120000;
  server.keepAliveTimeout = 65000;
}

startServer().catch(err => {
  console.error('Failed to start FileSentinel server:', err);
});
