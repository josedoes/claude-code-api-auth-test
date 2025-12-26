import * as jose from 'jose';
import { config } from '../../shared/config';
import { AuthContext } from '../../shared/types';

interface EgressResult {
  success: boolean;
  data?: unknown;
  error?: string;
}

class EgressClient {
  private secret: Uint8Array;

  constructor() {
    this.secret = new TextEncoder().encode(config.gateway.internalJwtSecret);
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
      return { success: false, error: String(error) };
    }
  }

  async reindex(authContext: AuthContext): Promise<EgressResult> {
    try {
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
      return { success: false, error: String(error) };
    }
  }
}

export const egressClient = new EgressClient();
