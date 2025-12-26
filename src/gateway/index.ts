import express from 'express';
import { config } from '../shared/config';
import { parseTestNowHeader } from '../shared/clock';
import { createAuthMiddleware } from './middleware/auth';
import { createRbacMiddleware } from './middleware/rbac';
import { createAbacMiddleware } from './middleware/abac';
import { createSessionMiddleware } from './middleware/session';
import { sessionStore } from './store/sessionStore';
import { reportStore } from './store/reportStore';
import { egressClient } from './egress/client';
import { createAuthRoutes } from './routes/auth';

const app = express();
app.use(express.json());

// Test time control middleware
if (config.isTest) {
  app.use((req, _res, next) => {
    parseTestNowHeader(req.headers['x-test-now'] as string);
    next();
  });
}

// Public routes
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'gateway' });
});

// Auth routes (refresh, logout)
const authRoutes = createAuthRoutes(sessionStore);
app.use('/auth', authRoutes);

// Protected route middleware chain
const authenticate = createAuthMiddleware();
const checkSession = createSessionMiddleware(sessionStore);
const rbac = createRbacMiddleware();
const abac = createAbacMiddleware(reportStore);

// Protected routes
// GET /reports/:id - read operation
app.get(
  '/reports/:id',
  authenticate,
  checkSession,
  rbac(['viewer', 'editor', 'admin']),
  async (req, res) => {
    const report = await reportStore.getById(req.params.id);
    if (!report) {
      res.status(404).json({ error: 'Report not found' });
      return;
    }
    res.json(report);
  }
);

// POST /reports - create operation (write)
app.post(
  '/reports',
  authenticate,
  checkSession,
  rbac(['editor', 'admin']),
  abac({ checkBusinessHours: true }),
  async (req, res) => {
    const report = await reportStore.create({
      ownerId: req.authContext!.sub,
      title: req.body.title || 'Untitled',
    });
    res.status(201).json(report);
  }
);

// POST /reports/:id/update - update operation (write, calls downstream)
app.post(
  '/reports/:id/update',
  authenticate,
  checkSession,
  rbac(['editor', 'admin']),
  abac({ checkOwnership: true, checkBusinessHours: true }),
  async (req, res) => {
    const report = await reportStore.getById(req.params.id);
    if (!report) {
      res.status(404).json({ error: 'Report not found' });
      return;
    }

    // Call downstream
    const result = await egressClient.updateReport(req.params.id, req.authContext!);
    if (!result.success) {
      res.status(500).json({ error: 'Downstream call failed' });
      return;
    }

    res.json({ success: true, reportId: req.params.id });
  }
);

// POST /admin/reindex - admin operation (calls downstream)
app.post(
  '/admin/reindex',
  authenticate,
  checkSession,
  rbac(['admin']),
  abac({ checkBusinessHours: true }),
  async (req, res) => {
    const result = await egressClient.reindex(req.authContext!);
    if (!result.success) {
      res.status(500).json({ error: 'Downstream call failed' });
      return;
    }

    res.json({ success: true, message: 'Reindex triggered' });
  }
);

// Initialize and start
async function start() {
  await sessionStore.connect();

  const port = config.gateway.port;
  app.listen(port, () => {
    console.log(`Gateway service listening on port ${port}`);
  });
}

if (require.main === module) {
  start().catch(console.error);
}

export { app, sessionStore, reportStore };
