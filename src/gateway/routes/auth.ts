import { Router } from 'express';
import * as jose from 'jose';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../../shared/config';
import { SessionStore } from '../store/sessionStore';
import { createAuthMiddleware } from '../middleware/auth';
import { Role } from '../../shared/types';

export function createAuthRoutes(sessionStore: SessionStore): Router {
  const router = Router();
  const secret = new TextEncoder().encode(config.gateway.jwtSecret);
  const authenticate = createAuthMiddleware();

  // Helper to create access token
  async function createAccessToken(
    userId: string,
    roles: Role[],
    sessionId: string,
    expiresInSeconds: number = 3600
  ): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const jti = uuidv4();

    return new jose.SignJWT({
      sub: userId,
      roles,
      sid: sessionId,
      jti,
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt(now)
      .setExpirationTime(now + expiresInSeconds)
      .setIssuer(config.gateway.jwtIssuer)
      .setAudience(config.gateway.jwtAudience)
      .sign(secret);
  }

  // POST /auth/refresh - Refresh token flow
  router.post('/refresh', async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      res.status(400).json({ error: 'Missing refresh token' });
      return;
    }

    try {
      // Check if refresh token was already used (replay attack)
      const alreadyUsed = await sessionStore.isRefreshTokenUsed(refreshToken);
      if (alreadyUsed) {
        res.status(401).json({ error: 'Refresh token already used' });
        return;
      }

      // Get session by refresh token
      const session = await sessionStore.getByRefreshToken(refreshToken);

      if (!session) {
        res.status(401).json({ error: 'Invalid refresh token' });
        return;
      }

      if (session.revoked) {
        res.status(401).json({ error: 'Session revoked' });
        return;
      }

      // Mark the old refresh token as used atomically
      const wasFirstUse = await sessionStore.markRefreshTokenUsed(refreshToken);
      if (!wasFirstUse) {
        // Race condition: another request already used this token
        res.status(401).json({ error: 'Refresh token already used' });
        return;
      }

      // Rotate refresh token
      const newRefreshToken = await sessionStore.rotateRefreshToken(session.id);

      if (!newRefreshToken) {
        res.status(401).json({ error: 'Failed to rotate refresh token' });
        return;
      }

      // SECURITY: Roles come from the session, NEVER from client input
      // This prevents privilege escalation attacks where an attacker
      // with a valid refresh token requests elevated roles
      const roles = session.roles;

      // Create new access token
      const accessToken = await createAccessToken(
        session.userId,
        roles,
        session.id
      );

      res.json({
        accessToken,
        refreshToken: newRefreshToken,
      });
    } catch (error) {
      res.status(500).json({ error: 'Refresh failed' });
    }
  });

  // POST /auth/logout - Logout flow
  router.post('/logout', authenticate, async (req, res) => {
    const authContext = req.authContext;

    if (!authContext) {
      res.status(401).json({ error: 'No auth context' });
      return;
    }

    try {
      const success = await sessionStore.revoke(authContext.sessionId);

      if (!success) {
        res.status(400).json({ error: 'Failed to revoke session' });
        return;
      }

      res.json({ success: true, message: 'Logged out' });
    } catch (error) {
      res.status(500).json({ error: 'Logout failed' });
    }
  });

  return router;
}
