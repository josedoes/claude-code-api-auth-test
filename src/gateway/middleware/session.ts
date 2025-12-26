import { Request, Response, NextFunction } from 'express';
import { SessionStore } from '../store/sessionStore';
import { getNow } from '../../shared/clock';

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

      // Session is valid
      next();
    } catch (error) {
      res.status(500).json({ error: 'Session check failed' });
    }
  };
}
