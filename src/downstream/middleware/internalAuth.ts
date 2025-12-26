import { Request, Response, NextFunction } from 'express';
import * as jose from 'jose';
import { config } from '../../shared/config';
import { InternalTokenPayload, AuthContext } from '../../shared/types';

// Extend Express Request to include auth context
declare global {
  namespace Express {
    interface Request {
      authContext?: AuthContext;
    }
  }
}

export function createInternalAuthMiddleware() {
  const secret = new TextEncoder().encode(config.downstream.internalJwtSecret);

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Missing or invalid authorization header' });
      return;
    }

    const token = authHeader.slice(7);

    try {
      // Verify the token
      const { payload, protectedHeader } = await jose.jwtVerify(token, secret, {
        issuer: config.downstream.internalJwtIssuer,
        audience: config.downstream.internalJwtAudience,
      });

      // Reject alg=none
      if (protectedHeader.alg === 'none') {
        res.status(401).json({ error: 'Invalid algorithm' });
        return;
      }

      const typedPayload = payload as unknown as InternalTokenPayload;

      // Attach auth context to request
      req.authContext = {
        sub: typedPayload.sub,
        roles: typedPayload.roles,
        sessionId: typedPayload.sessionId,
        jti: typedPayload.jti,
      };

      next();
    } catch (error) {
      if (error instanceof jose.errors.JWTExpired) {
        res.status(401).json({ error: 'Token expired' });
        return;
      }
      if (error instanceof jose.errors.JWTClaimValidationFailed) {
        res.status(401).json({ error: 'Invalid token claims' });
        return;
      }
      res.status(401).json({ error: 'Invalid token' });
    }
  };
}
