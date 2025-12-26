import { Request, Response, NextFunction } from 'express';
import { config } from '../../shared/config';

/**
 * CORS Middleware - Security-hardened implementation
 *
 * Security considerations:
 * 1. Explicit origin allowlist - never use '*' with credentials
 * 2. Reject null origin (used in some attack vectors)
 * 3. Vary header for proper caching
 * 4. Preflight caching with reasonable max-age
 * 5. Strict method and header allowlists
 */

const ALLOWED_METHODS = ['GET', 'POST', 'OPTIONS'];
const ALLOWED_HEADERS = ['Content-Type', 'Authorization', 'X-Requested-With'];
const EXPOSED_HEADERS = ['X-Request-Id']; // Headers client JS can read
const PREFLIGHT_MAX_AGE = 86400; // 24 hours - reduce preflight requests

export function createCorsMiddleware() {
  const allowedOrigins = new Set(config.gateway.corsAllowedOrigins);

  return (req: Request, res: Response, next: NextFunction): void => {
    const origin = req.headers.origin;

    // Always set Vary: Origin for proper caching behavior
    // This prevents cache poisoning attacks where a cached response
    // for one origin is served to another
    res.setHeader('Vary', 'Origin');

    // No Origin header = same-origin request or non-browser client
    // Allow these through without CORS headers
    if (!origin) {
      next();
      return;
    }

    // SECURITY: Reject 'null' origin
    // This can come from sandboxed iframes, local file:// pages,
    // or redirects - all potential attack vectors
    if (origin === 'null') {
      res.status(403).json({ error: 'Null origin not allowed' });
      return;
    }

    // SECURITY: Strict origin validation
    // Only allow explicitly configured origins
    if (!allowedOrigins.has(origin)) {
      // Don't include CORS headers - browser will block the response
      // Return 403 for clarity in logs, but browser won't see response anyway
      if (req.method === 'OPTIONS') {
        res.status(403).json({ error: 'Origin not allowed' });
        return;
      }
      // For non-preflight, proceed without CORS headers
      // The browser will block the response due to missing headers
      next();
      return;
    }

    // Origin is allowed - set CORS headers
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', ALLOWED_METHODS.join(', '));
    res.setHeader('Access-Control-Allow-Headers', ALLOWED_HEADERS.join(', '));
    res.setHeader('Access-Control-Expose-Headers', EXPOSED_HEADERS.join(', '));

    // Handle preflight requests
    if (req.method === 'OPTIONS') {
      // Cache preflight response to reduce roundtrips
      res.setHeader('Access-Control-Max-Age', String(PREFLIGHT_MAX_AGE));
      // 204 No Content is the standard response for successful preflight
      res.status(204).end();
      return;
    }

    next();
  };
}
