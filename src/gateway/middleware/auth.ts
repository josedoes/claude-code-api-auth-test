import { Request, Response, NextFunction } from 'express';
import * as jose from 'jose';
import { config } from '../../shared/config';
import { ExternalTokenPayload, AuthContext } from '../../shared/types';

// Extend Express Request to include auth context
declare global {
  namespace Express {
    interface Request {
      authContext?: AuthContext;
    }
  }
}

export function createAuthMiddleware() {
  const secret = new TextEncoder().encode(config.gateway.jwtSecret);

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const authHeader = req.headers.authorization;

    // Check for missing header
    if (!authHeader) {
      res.status(401).json({ error: 'Missing authorization header' });
      return;
    }

    // Check for malformed header
    if (!authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Malformed authorization header' });
      return;
    }

    const token = authHeader.slice(7);

    if (!token) {
      res.status(401).json({ error: 'Missing token' });
      return;
    }

    try {
      // First, decode the header to check the algorithm before verification
      const tokenParts = token.split('.');
      if (tokenParts.length !== 3) {
        res.status(401).json({ error: 'Invalid token format' });
        return;
      }

      // Decode header to check algorithm
      let header: { alg?: string };
      try {
        header = JSON.parse(Buffer.from(tokenParts[0], 'base64url').toString());
      } catch {
        res.status(401).json({ error: 'Invalid token header' });
        return;
      }

      // Reject alg=none explicitly before verification
      if (header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE') {
        res.status(401).json({ error: 'Algorithm none not allowed' });
        return;
      }

      // Only allow HS256
      if (header.alg !== 'HS256') {
        res.status(401).json({ error: 'Unexpected algorithm' });
        return;
      }

      // Verify the token
      const { payload } = await jose.jwtVerify(token, secret, {
        issuer: config.gateway.jwtIssuer,
        audience: config.gateway.jwtAudience,
      });

      const typedPayload = payload as unknown as ExternalTokenPayload;

      // Validate required claims
      if (!typedPayload.sub || !typedPayload.roles || !typedPayload.jti || !typedPayload.sid) {
        res.status(401).json({ error: 'Missing required claims' });
        return;
      }

      // Attach auth context to request
      req.authContext = {
        sub: typedPayload.sub,
        roles: typedPayload.roles,
        sessionId: typedPayload.sid,
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
      if (error instanceof jose.errors.JWSSignatureVerificationFailed) {
        res.status(401).json({ error: 'Invalid signature' });
        return;
      }
      res.status(401).json({ error: 'Invalid token' });
    }
  };
}
