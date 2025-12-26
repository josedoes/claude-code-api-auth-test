import * as jose from 'jose';
import { config } from '../../shared/config';
import { AuthContext, Role } from '../../shared/types';

interface EgressResult {
  success: boolean;
  data?: unknown;
  error?: string;
}

/**
 * Egress authorization error - thrown when egress policy denies the call
 */
export class EgressAuthorizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EgressAuthorizationError';
  }
}

/**
 * Egress Policy Map - explicit authorization requirements for each downstream operation
 * This provides defense-in-depth: even if a handler forgets middleware,
 * the egress client itself enforces authorization before making calls.
 */
const EGRESS_POLICY = {
  'report:update': {
    requiredRoles: ['editor', 'admin'] as Role[],
    description: 'Update report via downstream service',
  },
  'admin:reindex': {
    requiredRoles: ['admin'] as Role[],
    description: 'Trigger reindex via downstream service',
  },
} as const;

class EgressClient {
  private secret: Uint8Array;

  constructor() {
    this.secret = new TextEncoder().encode(config.gateway.internalJwtSecret);
  }

  /**
   * Explicit egress authorization check - runs BEFORE any downstream call
   * This is defense-in-depth: the egress client enforces its own policy
   */
  private assertEgressAuthorization(
    operation: keyof typeof EGRESS_POLICY,
    authContext: AuthContext
  ): void {
    const policy = EGRESS_POLICY[operation];
    const hasRequiredRole = authContext.roles.some(role =>
      policy.requiredRoles.includes(role)
    );

    if (!hasRequiredRole) {
      throw new EgressAuthorizationError(
        `Egress denied: ${operation} requires one of [${policy.requiredRoles.join(', ')}], ` +
        `but user has [${authContext.roles.join(', ')}]`
      );
    }
  }

  private async createInternalToken(authContext: AuthContext): Promise<string> {
    const now = Math.floor(Date.now() / 1000);

    const token = await new jose.SignJWT({
      sub: authContext.sub,
      roles: authContext.roles,
      sessionId: authContext.sessionId,
      jti: authContext.jti,
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt(now)
      .setExpirationTime(now + 60) // 1 minute expiry
      .setIssuer('gateway')
      .setAudience('downstream')
      .sign(this.secret);

    return token;
  }

  async updateReport(reportId: string, authContext: AuthContext): Promise<EgressResult> {
    try {
      // SECURITY: Explicit egress authorization check BEFORE downstream call
      this.assertEgressAuthorization('report:update', authContext);

      const token = await this.createInternalToken(authContext);

      const response = await fetch(
        `${config.gateway.downstreamUrl}/internal/report/${reportId}/update`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ reportId }),
        }
      );

      if (!response.ok) {
        return { success: false, error: `Downstream returned ${response.status}` };
      }

      const data = await response.json();
      return { success: true, data };
    } catch (error) {
      if (error instanceof EgressAuthorizationError) {
        return { success: false, error: error.message };
      }
      return { success: false, error: String(error) };
    }
  }

  async reindex(authContext: AuthContext): Promise<EgressResult> {
    try {
      // SECURITY: Explicit egress authorization check BEFORE downstream call
      this.assertEgressAuthorization('admin:reindex', authContext);

      const token = await this.createInternalToken(authContext);

      const response = await fetch(
        `${config.gateway.downstreamUrl}/internal/reindex`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({}),
        }
      );

      if (!response.ok) {
        return { success: false, error: `Downstream returned ${response.status}` };
      }

      const data = await response.json();
      return { success: true, data };
    } catch (error) {
      if (error instanceof EgressAuthorizationError) {
        return { success: false, error: error.message };
      }
      return { success: false, error: String(error) };
    }
  }
}

export const egressClient = new EgressClient();
