import { Request, Response, NextFunction } from 'express';
import { SessionStore } from '../store/sessionStore';
import { getNow } from '../../shared/clock';

/**
 * Session Middleware - Associates JWT with session and enforces session authority
 *
 * SECURITY: This middleware enforces that:
 * 1. JWT's session ID (sid) maps to a valid, non-revoked, non-expired session
 * 2. JWT's subject (sub) matches the session's userId - prevents session hijacking
 * 3. Session's roles become authoritative - prevents role tampering via JWT modification
 *
 * The session is the source of truth for roles, not the JWT. This means:
 * - Roles are immutably set at session creation
 * - Even if someone modifies JWT roles, session roles are used
 * - Role changes require new session (re-authentication)
 */
export function createSessionMiddleware(sessionStore: SessionStore) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const authContext = req.authContext;

    if (!authContext) {
      res.status(401).json({ error: 'No auth context' });
      return;
    }

    try {
      const session = await sessionStore.getById(authContext.sessionId);

      if (!session) {
        res.status(401).json({ error: 'Session not found' });
        return;
      }

      if (session.revoked) {
        res.status(401).json({ error: 'Session revoked' });
        return;
      }

      const now = getNow().getTime();
      if (session.expiresAt < now) {
        res.status(401).json({ error: 'Session expired' });
        return;
      }

      // SECURITY: Verify JWT subject matches session owner
      // This prevents session ID theft/reuse attacks where an attacker
      // tries to use another user's session ID in their own JWT
      if (session.userId !== authContext.sub) {
        res.status(401).json({ error: 'Session user mismatch' });
        return;
      }

      // SECURITY: Override JWT roles with session's authoritative roles
      // Session roles are immutable and set at creation time
      // This is the key association between session and JWT identity
      authContext.roles = session.roles;

      // Session is valid and associated with JWT
      next();
    } catch (error) {
      res.status(500).json({ error: 'Session check failed' });
    }
  };
}
