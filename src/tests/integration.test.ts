import request from 'supertest';
import { v4 as uuidv4 } from 'uuid';
import { app as gatewayApp, sessionStore, reportStore } from '../gateway/index';
import { app as downstreamApp } from '../downstream/index';
import { callCounter } from '../downstream/callCounter';
import { setTestNow } from '../shared/clock';
import {
  createTestToken,
  createTokenWithWrongSignature,
  createAlgNoneToken,
  createExpiredToken,
} from './helpers';
import { Report } from '../shared/types';
import http from 'http';

// Test fixtures
const USERS = {
  userA: { sub: 'userA', roles: ['viewer', 'editor'] as const },
  userB: { sub: 'userB', roles: ['viewer'] as const },
  admin1: { sub: 'admin1', roles: ['admin'] as const },
  viewerOnly: { sub: 'viewerOnly', roles: ['viewer'] as const },
  editorOnly: { sub: 'editorOnly', roles: ['editor'] as const },
};

const REPORTS: Report[] = [
  { id: 'r1', ownerId: 'userA', title: 'Report 1' },
  { id: 'r2', ownerId: 'userB', title: 'Report 2' },
];

// Toronto business hours: 09:00-17:00
// During EST (winter): UTC-5, so 09:00 Toronto = 14:00 UTC, 17:00 Toronto = 22:00 UTC
// During EDT (summer): UTC-4, so 09:00 Toronto = 13:00 UTC, 17:00 Toronto = 21:00 UTC
const BUSINESS_HOURS_TIME = new Date('2024-01-15T15:00:00Z'); // 10:00 AM Toronto (EST)
const OUTSIDE_BUSINESS_HOURS_TIME = new Date('2024-01-15T01:00:00Z'); // 8:00 PM Toronto (EST)

let gatewayServer: http.Server;
let downstreamServer: http.Server;

beforeAll(async () => {
  // Start downstream server first
  await new Promise<void>((resolve) => {
    downstreamServer = downstreamApp.listen(3001, resolve);
  });

  // Connect session store and start gateway
  await sessionStore.connect();

  await new Promise<void>((resolve) => {
    gatewayServer = gatewayApp.listen(3000, resolve);
  });
});

afterAll(async () => {
  await new Promise<void>((resolve) => {
    gatewayServer.close(() => resolve());
  });
  await new Promise<void>((resolve) => {
    downstreamServer.close(() => resolve());
  });
  await sessionStore.disconnect();
});

beforeEach(async () => {
  // Reset state before each test
  reportStore.seed(REPORTS);
  callCounter.reset();
  setTestNow(BUSINESS_HOURS_TIME); // Default to business hours

  // Reset downstream call counter
  await request(downstreamApp).post('/__calls/reset');
});

afterEach(() => {
  setTestNow(null);
});

// Helper to create a session and token
async function createSessionAndToken(
  userId: string,
  roles: readonly string[],
  ttlMs: number = 3600000
): Promise<{ token: string; sessionId: string; refreshToken: string }> {
  // Roles are now stored in the session - this prevents privilege escalation
  const { session, refreshToken } = await sessionStore.create(userId, roles as any, ttlMs);
  const token = await createTestToken({
    sub: userId,
    roles: roles as any,
    sid: session.id,
  });
  return { token, sessionId: session.id, refreshToken };
}

// Helper to get downstream call counts
async function getDownstreamCalls(): Promise<{ reportUpdate: number; reindex: number }> {
  const res = await request(downstreamApp).get('/__calls');
  return res.body;
}

// ==========================================
// A) Baseline: Public Route
// ==========================================

describe('A) Baseline: Public Route', () => {
  test('1. GET /health returns 200 without Authorization', async () => {
    const res = await request(gatewayApp).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });
});

// ==========================================
// B) JWT Authentication (Ingress)
// ==========================================

describe('B) JWT Authentication (Ingress)', () => {
  test('2. Missing token returns 401', async () => {
    const res = await request(gatewayApp).get('/reports/r1');
    expect(res.status).toBe(401);
  });

  test('3. Malformed Authorization header returns 401', async () => {
    const res = await request(gatewayApp)
      .get('/reports/r1')
      .set('Authorization', 'NotBearer token');
    expect(res.status).toBe(401);
  });

  test('4. Invalid signature returns 401', async () => {
    const token = await createTokenWithWrongSignature({ sub: 'userA' });
    const res = await request(gatewayApp)
      .get('/reports/r1')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(401);
  });

  test('5. Wrong issuer returns 401', async () => {
    const { session } = await sessionStore.create('userA', ['viewer'], 3600000);
    const token = await createTestToken({
      sub: 'userA',
      roles: ['viewer'],
      sid: session.id,
      iss: 'wrong-issuer',
    });
    const res = await request(gatewayApp)
      .get('/reports/r1')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(401);
  });

  test('6. Wrong audience returns 401', async () => {
    const { session } = await sessionStore.create('userA', ['viewer'], 3600000);
    const token = await createTestToken({
      sub: 'userA',
      roles: ['viewer'],
      sid: session.id,
      aud: 'wrong-audience',
    });
    const res = await request(gatewayApp)
      .get('/reports/r1')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(401);
  });

  test('7. Expired token returns 401', async () => {
    const token = await createExpiredToken({ sub: 'userA', roles: ['viewer'] });
    const res = await request(gatewayApp)
      .get('/reports/r1')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(401);
  });

  test('8. alg=none token returns 401', async () => {
    const token = createAlgNoneToken({ sub: 'userA', roles: ['admin'] });
    const res = await request(gatewayApp)
      .get('/reports/r1')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(401);
  });

  test('9. Valid JWT returns 200', async () => {
    const { token } = await createSessionAndToken('userA', ['viewer']);
    const res = await request(gatewayApp)
      .get('/reports/r1')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
  });
});

// ==========================================
// C) RBAC (Ingress)
// ==========================================

describe('C) RBAC (Ingress)', () => {
  test('10. Viewer can read reports', async () => {
    const { token } = await createSessionAndToken('viewerOnly', ['viewer']);
    const res = await request(gatewayApp)
      .get('/reports/r1')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
  });

  test('11. Viewer cannot write (POST /reports)', async () => {
    const { token } = await createSessionAndToken('viewerOnly', ['viewer']);
    const res = await request(gatewayApp)
      .post('/reports')
      .set('Authorization', `Bearer ${token}`)
      .send({ title: 'New Report' });
    expect(res.status).toBe(403);
  });

  test('12. Editor can write (POST /reports)', async () => {
    const { token } = await createSessionAndToken('editorOnly', ['editor']);
    const res = await request(gatewayApp)
      .post('/reports')
      .set('Authorization', `Bearer ${token}`)
      .send({ title: 'New Report' });
    expect(res.status).toBe(201);
  });

  test('13. Editor cannot access admin route (POST /admin/reindex)', async () => {
    const { token } = await createSessionAndToken('editorOnly', ['editor']);
    const res = await request(gatewayApp)
      .post('/admin/reindex')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
  });

  test('14. Admin can access admin route', async () => {
    const { token } = await createSessionAndToken('admin1', ['admin']);
    const res = await request(gatewayApp)
      .post('/admin/reindex')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
  });
});

// ==========================================
// D) RBAC (Egress)
// ==========================================

describe('D) RBAC (Egress)', () => {
  test('15. Viewer denied admin route - downstream NOT called', async () => {
    const { token } = await createSessionAndToken('viewerOnly', ['viewer']);
    const callsBefore = await getDownstreamCalls();

    const res = await request(gatewayApp)
      .post('/admin/reindex')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(403);

    const callsAfter = await getDownstreamCalls();
    expect(callsAfter.reindex).toBe(callsBefore.reindex);
  });

  test('16. Admin allowed admin route - downstream called exactly once', async () => {
    const { token } = await createSessionAndToken('admin1', ['admin']);
    const callsBefore = await getDownstreamCalls();

    const res = await request(gatewayApp)
      .post('/admin/reindex')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);

    const callsAfter = await getDownstreamCalls();
    expect(callsAfter.reindex).toBe(callsBefore.reindex + 1);
  });

  test('17. Editor calling update operation - allowed and increments counter', async () => {
    // userA is the owner of r1, so editor role + ownership allows update
    const { token } = await createSessionAndToken('userA', ['editor']);
    const callsBefore = await getDownstreamCalls();

    const res = await request(gatewayApp)
      .post('/reports/r1/update')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);

    const callsAfter = await getDownstreamCalls();
    expect(callsAfter.reportUpdate).toBe(callsBefore.reportUpdate + 1);
  });
});

// ==========================================
// E) ABAC Policy (Ingress)
// ==========================================

describe('E) ABAC Policy (Ingress)', () => {
  test('18. Owner can update during business hours', async () => {
    setTestNow(BUSINESS_HOURS_TIME);
    const { token } = await createSessionAndToken('userA', ['editor']);

    const res = await request(gatewayApp)
      .post('/reports/r1/update')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Test-Now', BUSINESS_HOURS_TIME.toISOString());

    expect(res.status).toBe(200);
  });

  test('19. Non-owner cannot update during business hours', async () => {
    setTestNow(BUSINESS_HOURS_TIME);
    const { token } = await createSessionAndToken('userB', ['editor']);

    const res = await request(gatewayApp)
      .post('/reports/r1/update')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Test-Now', BUSINESS_HOURS_TIME.toISOString());

    expect(res.status).toBe(403);
  });

  test('20. Admin can update any report during business hours (ownership bypass)', async () => {
    setTestNow(BUSINESS_HOURS_TIME);
    const { token } = await createSessionAndToken('admin1', ['admin']);

    const res = await request(gatewayApp)
      .post('/reports/r1/update')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Test-Now', BUSINESS_HOURS_TIME.toISOString());

    expect(res.status).toBe(200);
  });

  test('21. Owner denied outside business hours', async () => {
    setTestNow(OUTSIDE_BUSINESS_HOURS_TIME);
    const { token } = await createSessionAndToken('userA', ['editor']);

    const res = await request(gatewayApp)
      .post('/reports/r1/update')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Test-Now', OUTSIDE_BUSINESS_HOURS_TIME.toISOString());

    expect(res.status).toBe(403);
  });

  test('22. Admin denied outside business hours (business hours apply to all)', async () => {
    setTestNow(OUTSIDE_BUSINESS_HOURS_TIME);
    const { token } = await createSessionAndToken('admin1', ['admin']);

    const res = await request(gatewayApp)
      .post('/reports/r1/update')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Test-Now', OUTSIDE_BUSINESS_HOURS_TIME.toISOString());

    expect(res.status).toBe(403);
  });
});

// ==========================================
// F) ABAC Enforcement on Egress
// ==========================================

describe('F) ABAC Enforcement on Egress', () => {
  test('23. ABAC deny (non-owner) - downstream NOT called', async () => {
    setTestNow(BUSINESS_HOURS_TIME);
    const { token } = await createSessionAndToken('userB', ['editor']);
    const callsBefore = await getDownstreamCalls();

    const res = await request(gatewayApp)
      .post('/reports/r1/update')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Test-Now', BUSINESS_HOURS_TIME.toISOString());

    expect(res.status).toBe(403);

    const callsAfter = await getDownstreamCalls();
    expect(callsAfter.reportUpdate).toBe(callsBefore.reportUpdate);
  });

  test('24. ABAC allow (owner) - downstream called once', async () => {
    setTestNow(BUSINESS_HOURS_TIME);
    const { token } = await createSessionAndToken('userA', ['editor']);
    const callsBefore = await getDownstreamCalls();

    const res = await request(gatewayApp)
      .post('/reports/r1/update')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Test-Now', BUSINESS_HOURS_TIME.toISOString());

    expect(res.status).toBe(200);

    const callsAfter = await getDownstreamCalls();
    expect(callsAfter.reportUpdate).toBe(callsBefore.reportUpdate + 1);
  });

  test('25. Downstream receives verified identity context', async () => {
    setTestNow(BUSINESS_HOURS_TIME);
    const { token } = await createSessionAndToken('userA', ['editor']);

    await request(gatewayApp)
      .post('/reports/r1/update')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Test-Now', BUSINESS_HOURS_TIME.toISOString());

    const identityRes = await request(downstreamApp).get('/__last-identity');
    expect(identityRes.body.sub).toBe('userA');
    expect(identityRes.body.roles).toContain('editor');
  });

  test('26. Header spoofing attempt fails - still treated as viewer', async () => {
    const { token } = await createSessionAndToken('viewerOnly', ['viewer']);
    const callsBefore = await getDownstreamCalls();

    const res = await request(gatewayApp)
      .post('/admin/reindex')
      .set('Authorization', `Bearer ${token}`)
      .set('X-User', 'admin1')
      .set('X-Roles', 'admin');

    expect(res.status).toBe(403);

    const callsAfter = await getDownstreamCalls();
    expect(callsAfter.reindex).toBe(callsBefore.reindex);
  });
});

// ==========================================
// G) Session Management
// ==========================================

describe('G) Session Management', () => {
  describe('Refresh Flow', () => {
    test('27. Valid refresh token returns new tokens', async () => {
      const { refreshToken } = await createSessionAndToken('userA', ['editor']);

      // Note: roles are NOT sent - they come from the session
      const res = await request(gatewayApp)
        .post('/auth/refresh')
        .send({ refreshToken });

      expect(res.status).toBe(200);
      expect(res.body.accessToken).toBeDefined();
      expect(res.body.refreshToken).toBeDefined();
      expect(res.body.refreshToken).not.toBe(refreshToken); // Rotated
    });

    test('28. Refresh token reuse is rejected', async () => {
      const { refreshToken } = await createSessionAndToken('userA', ['editor']);

      // First use - should succeed
      const res1 = await request(gatewayApp)
        .post('/auth/refresh')
        .send({ refreshToken });
      expect(res1.status).toBe(200);

      // Second use - should fail
      const res2 = await request(gatewayApp)
        .post('/auth/refresh')
        .send({ refreshToken });
      expect(res2.status).toBe(401);
    });

    test('29. Invalid refresh token rejected', async () => {
      const res = await request(gatewayApp)
        .post('/auth/refresh')
        .send({ refreshToken: 'invalid-token' });

      expect(res.status).toBe(401);
    });
  });

  describe('Logout Flow', () => {
    test('30. Logout invalidates session', async () => {
      const { token } = await createSessionAndToken('userA', ['editor']);

      const res = await request(gatewayApp)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    test('31. Post-logout refresh rejected', async () => {
      const { token, refreshToken } = await createSessionAndToken('userA', ['editor']);

      // Logout
      await request(gatewayApp)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${token}`);

      // Try to refresh
      const res = await request(gatewayApp)
        .post('/auth/refresh')
        .send({ refreshToken });

      expect(res.status).toBe(401);
    });

    test('32. Post-logout access token rejected', async () => {
      const { token } = await createSessionAndToken('userA', ['editor']);

      // Logout
      await request(gatewayApp)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${token}`);

      // Try to use the same token
      const res = await request(gatewayApp)
        .get('/reports/r1')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(401);
    });

    test('33. Post-logout egress denied - downstream NOT called', async () => {
      setTestNow(BUSINESS_HOURS_TIME);
      const { token } = await createSessionAndToken('userA', ['editor']);

      // Logout
      await request(gatewayApp)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${token}`);

      const callsBefore = await getDownstreamCalls();

      // Try to call downstream-triggering endpoint
      const res = await request(gatewayApp)
        .post('/reports/r1/update')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Test-Now', BUSINESS_HOURS_TIME.toISOString());

      expect(res.status).toBe(401);

      const callsAfter = await getDownstreamCalls();
      expect(callsAfter.reportUpdate).toBe(callsBefore.reportUpdate);
    });
  });

  describe('Session TTL', () => {
    test('34. Session expires before JWT - request fails', async () => {
      // Create session with 5 second TTL, but JWT has 1 hour exp
      const { session, refreshToken } = await sessionStore.create('userA', ['editor'], 5000);

      const token = await createTestToken({
        sub: 'userA',
        roles: ['editor'],
        sid: session.id,
        exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
      });

      // Advance time by 6 seconds (session expired, JWT still valid)
      const futureTime = new Date(Date.now() + 6000);
      setTestNow(futureTime);

      const res = await request(gatewayApp)
        .get('/reports/r1')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Test-Now', futureTime.toISOString());

      expect(res.status).toBe(401);
    });
  });

  describe('Concurrency Safety', () => {
    test('35. Double refresh race - exactly one succeeds', async () => {
      const { refreshToken } = await createSessionAndToken('userA', ['editor']);

      // Attempt two concurrent refreshes
      const [res1, res2] = await Promise.all([
        request(gatewayApp)
          .post('/auth/refresh')
          .send({ refreshToken }),
        request(gatewayApp)
          .post('/auth/refresh')
          .send({ refreshToken }),
      ]);

      const successCount = [res1, res2].filter(r => r.status === 200).length;
      const failCount = [res1, res2].filter(r => r.status === 401).length;

      expect(successCount).toBe(1);
      expect(failCount).toBe(1);
    });
  });

  describe('Privilege Escalation Prevention', () => {
    test('36. Refresh with requested admin role - still gets original viewer role', async () => {
      // Create a viewer-only session
      const { refreshToken } = await createSessionAndToken('viewerOnly', ['viewer']);

      // Attacker attempts to escalate by requesting admin role
      const res = await request(gatewayApp)
        .post('/auth/refresh')
        .send({ refreshToken, roles: ['admin'] }); // Malicious payload

      expect(res.status).toBe(200);

      // Use the new token to try admin route
      const adminRes = await request(gatewayApp)
        .post('/admin/reindex')
        .set('Authorization', `Bearer ${res.body.accessToken}`);

      // Should still be forbidden - roles came from session, not request
      expect(adminRes.status).toBe(403);
    });

    test('37. Refresh ignores all client-provided role combinations', async () => {
      // Create editor session
      const { refreshToken } = await createSessionAndToken('editorOnly', ['editor']);

      // Try various escalation attempts
      const escalationAttempts = [
        { roles: ['admin'] },
        { roles: ['admin', 'editor', 'viewer'] },
        { roles: ['superadmin'] }, // Invalid role
        { roles: [] }, // Empty roles
      ];

      for (const payload of escalationAttempts) {
        const res = await request(gatewayApp)
          .post('/auth/refresh')
          .send({ refreshToken: (await createSessionAndToken('editorOnly', ['editor'])).refreshToken, ...payload });

        expect(res.status).toBe(200);

        // Verify cannot access admin route
        const adminRes = await request(gatewayApp)
          .post('/admin/reindex')
          .set('Authorization', `Bearer ${res.body.accessToken}`);
        expect(adminRes.status).toBe(403);
      }
    });
  });
});

// ==========================================
// H) Downstream Direct-Access Protection
// ==========================================

describe('H) Downstream Direct-Access Protection', () => {
  test('38. Direct call to downstream without internal auth returns 401', async () => {
    const res = await request(downstreamApp)
      .post('/internal/reindex')
      .send({});

    expect(res.status).toBe(401);
  });

  test('39. Downstream rejects forged internal token', async () => {
    // Create token with wrong signing key
    const wrongSecret = new TextEncoder().encode('wrong-internal-secret');
    const jose = require('jose');

    const now = Math.floor(Date.now() / 1000);
    const forgedToken = await new jose.SignJWT({
      sub: 'attacker',
      roles: ['admin'],
      sessionId: 'fake-session',
      jti: 'fake-jti',
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt(now)
      .setExpirationTime(now + 60)
      .setIssuer('gateway')
      .setAudience('downstream')
      .sign(wrongSecret);

    const res = await request(downstreamApp)
      .post('/internal/reindex')
      .set('Authorization', `Bearer ${forgedToken}`)
      .send({});

    expect(res.status).toBe(401);
  });
});

// ==========================================
// I) CORS Security
// ==========================================

describe('I) CORS Security', () => {
  test('40. Preflight from allowed origin returns CORS headers', async () => {
    const res = await request(gatewayApp)
      .options('/reports/r1')
      .set('Origin', 'https://trusted.example.com')
      .set('Access-Control-Request-Method', 'GET');

    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-origin']).toBe('https://trusted.example.com');
    expect(res.headers['access-control-allow-credentials']).toBe('true');
    expect(res.headers['access-control-allow-methods']).toContain('GET');
  });

  test('41. Preflight from disallowed origin returns 403', async () => {
    const res = await request(gatewayApp)
      .options('/reports/r1')
      .set('Origin', 'https://malicious.example.com')
      .set('Access-Control-Request-Method', 'GET');

    expect(res.status).toBe(403);
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });

  test('42. Null origin is rejected', async () => {
    const res = await request(gatewayApp)
      .options('/reports/r1')
      .set('Origin', 'null')
      .set('Access-Control-Request-Method', 'GET');

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('Null origin not allowed');
  });

  test('43. Request from allowed origin includes CORS headers', async () => {
    const { token } = await createSessionAndToken('userA', ['viewer']);

    const res = await request(gatewayApp)
      .get('/reports/r1')
      .set('Origin', 'https://trusted.example.com')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBe('https://trusted.example.com');
    expect(res.headers['vary']).toContain('Origin');
  });

  test('44. Request from disallowed origin has no CORS headers', async () => {
    const { token } = await createSessionAndToken('userA', ['viewer']);

    const res = await request(gatewayApp)
      .get('/reports/r1')
      .set('Origin', 'https://malicious.example.com')
      .set('Authorization', `Bearer ${token}`);

    // Request succeeds (server-side), but no CORS headers
    // Browser would block the response
    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });

  test('45. Vary: Origin header always present for caching correctness', async () => {
    const { token } = await createSessionAndToken('userA', ['viewer']);

    // With allowed origin
    const res1 = await request(gatewayApp)
      .get('/reports/r1')
      .set('Origin', 'https://trusted.example.com')
      .set('Authorization', `Bearer ${token}`);
    expect(res1.headers['vary']).toContain('Origin');

    // Without origin (same-origin request)
    const res2 = await request(gatewayApp)
      .get('/reports/r1')
      .set('Authorization', `Bearer ${token}`);
    expect(res2.headers['vary']).toContain('Origin');
  });
});

// ==========================================
// J) Regression / Invariants
// ==========================================

describe('J) Regression / Invariants', () => {
  test('46. All write endpoints enforce complete auth chain', async () => {
    // Test POST /reports without token
    const res1 = await request(gatewayApp).post('/reports').send({ title: 'Test' });
    expect([401, 403]).toContain(res1.status);

    // Test POST /reports/:id/update without token
    const res2 = await request(gatewayApp).post('/reports/r1/update').send({});
    expect([401, 403]).toContain(res2.status);

    // Test POST /admin/reindex without token
    const res3 = await request(gatewayApp).post('/admin/reindex').send({});
    expect([401, 403]).toContain(res3.status);
  });

  test('47. No 500 errors for expected authz failures', async () => {
    // Various auth failures should return 4xx, not 5xx
    const responses = await Promise.all([
      request(gatewayApp).get('/reports/r1'), // no token
      request(gatewayApp).get('/reports/r1').set('Authorization', 'Bearer invalid'),
      request(gatewayApp).get('/reports/r1').set('Authorization', 'NotBearer token'),
    ]);

    responses.forEach(res => {
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(res.status).toBeLessThan(500);
    });
  });

  test('48. Forbidden requests are side-effect free', async () => {
    setTestNow(BUSINESS_HOURS_TIME);

    // Create a viewer token (no write permissions)
    const { token } = await createSessionAndToken('viewerOnly', ['viewer']);
    const callsBefore = await getDownstreamCalls();

    // Attempt forbidden operations
    await request(gatewayApp)
      .post('/reports')
      .set('Authorization', `Bearer ${token}`)
      .send({ title: 'Forbidden Report' });

    await request(gatewayApp)
      .post('/admin/reindex')
      .set('Authorization', `Bearer ${token}`);

    const callsAfter = await getDownstreamCalls();

    // No downstream calls should have been made
    expect(callsAfter.reportUpdate).toBe(callsBefore.reportUpdate);
    expect(callsAfter.reindex).toBe(callsBefore.reindex);
  });
});
