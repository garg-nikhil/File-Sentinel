import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { createApiRouter } from './backend/routes.js';
import { securityHeaders, corsMiddleware, enforceContentType, rateLimiter, csrfProtection, safeErrorHandler } from './backend/securityMiddleware.js';
import { FileIntegrityMonitor } from './backend/fimService.js';

async function startServer() {
  const fimResult = FileIntegrityMonitor.verifyIntegrity();
  if (!fimResult.valid) {
    console.warn('[FIM Warning] File integrity check flagged files:', fimResult.modifiedFiles);
  } else {
    console.log('[FIM] File integrity check passed successfully.');
  }

  const app = express();
  const PORT = 3000;

  // Security Middleware
  app.use(securityHeaders);
  app.use(corsMiddleware);
  app.use(express.json({ limit: '100kb' }));
  app.use(enforceContentType);
  app.use(csrfProtection);

  // Rate limiters for sensitive endpoints
  const authRateLimiter = rateLimiter({ windowMs: 60000, max: 20 });
  const apiRateLimiter = rateLimiter({ windowMs: 60000, max: 150 });
  const webhookRateLimiter = rateLimiter({ windowMs: 60000, max: 200 });

  app.use('/api/auth/login', authRateLimiter);
  app.use('/api/webhooks', webhookRateLimiter);
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

  const HOST = process.env.HOST || (process.env.TAURI_DESKTOP ? '127.0.0.1' : '0.0.0.0');

  const server = app.listen(PORT, HOST, () => {
    console.log(`[FileSentinel] Local-First Security Server running on http://${HOST}:${PORT}`);
  });

  server.headersTimeout = 60000;
  server.requestTimeout = 120000;
  server.keepAliveTimeout = 65000;
}

startServer().catch(err => {
  console.error('Failed to start FileSentinel server:', err);
});
