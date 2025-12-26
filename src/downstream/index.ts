import express from 'express';
import { config } from '../shared/config';
import { createInternalAuthMiddleware } from './middleware/internalAuth';
import { callCounter } from './callCounter';

const app = express();
app.use(express.json());

// Internal auth middleware for protected routes
const internalAuth = createInternalAuthMiddleware();

// Test-only endpoint to get call counts
if (config.isTest) {
  app.get('/__calls', (_req, res) => {
    res.json(callCounter.getCounts());
  });

  app.post('/__calls/reset', (_req, res) => {
    callCounter.reset();
    res.json({ reset: true });
  });

  app.get('/__last-identity', (_req, res) => {
    res.json(callCounter.getLastIdentity());
  });
}

// Internal routes - require valid internal JWT
app.post('/internal/report/:id/update', internalAuth, (req, res) => {
  callCounter.increment('reportUpdate');
  callCounter.recordIdentity(req.authContext!);
  res.json({ success: true, reportId: req.params.id });
});

app.post('/internal/reindex', internalAuth, (req, res) => {
  callCounter.increment('reindex');
  callCounter.recordIdentity(req.authContext!);
  res.json({ success: true, message: 'Reindex complete' });
});

// Health check
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'downstream' });
});

// Start server if run directly
if (require.main === module) {
  const port = config.downstream.port;
  app.listen(port, () => {
    console.log(`Downstream service listening on port ${port}`);
  });
}

export { app };
