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
      // SECURITY: Pre-verification algorithm check
      // Reject alg=none BEFORE verification to prevent algorithm confusion attacks
      const tokenParts = token.split('.');
      if (tokenParts.length !== 3) {
        res.status(401).json({ error: 'Invalid token format' });
        return;
      }

      let header: { alg?: string };
      try {
        header = JSON.parse(Buffer.from(tokenParts[0], 'base64url').toString());
      } catch {
        res.status(401).json({ error: 'Invalid token header' });
        return;
      }

      if (header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE') {
        res.status(401).json({ error: 'Algorithm none not allowed' });
        return;
      }

      if (header.alg !== 'HS256') {
        res.status(401).json({ error: 'Unexpected algorithm' });
        return;
      }

      // Verify the token
      const { payload } = await jose.jwtVerify(token, secret, {
        issuer: config.downstream.internalJwtIssuer,
        audience: config.downstream.internalJwtAudience,
      });

      const typedPayload = payload as unknown as InternalTokenPayload;

      // SECURITY: Validate required claims exist
      // Defense-in-depth: don't trust that gateway sent complete identity
      if (!typedPayload.sub || typeof typedPayload.sub !== 'string') {
        res.status(401).json({ error: 'Missing required claim: sub' });
        return;
      }
      if (!typedPayload.roles || !Array.isArray(typedPayload.roles) || typedPayload.roles.length === 0) {
        res.status(401).json({ error: 'Missing required claim: roles' });
        return;
      }
      if (!typedPayload.sessionId || typeof typedPayload.sessionId !== 'string') {
        res.status(401).json({ error: 'Missing required claim: sessionId' });
        return;
      }
      if (!typedPayload.jti || typeof typedPayload.jti !== 'string') {
        res.status(401).json({ error: 'Missing required claim: jti' });
        return;
      }

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
