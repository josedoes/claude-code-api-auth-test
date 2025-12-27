import { Request, Response, NextFunction } from 'express';
import { getNow } from '../../shared/clock';
import { ReportStore } from '../store/reportStore';
import { Role } from '../../shared/types';

interface AbacOptions {
  checkOwnership?: boolean;
  checkBusinessHours?: boolean;
}

/**
 * ABAC Policy Map - Explicit attribute-based permissions for EACH role
 *
 * This evaluates request parameters against the policy for ALL roles the user has.
 * Access is granted if ANY of the user's roles permits the action.
 *
 * SECURITY: Each role explicitly defines its attribute-based capabilities.
 * This makes the security model auditable and prevents implicit assumptions.
 */
const ABAC_POLICY: Record<Role, {
  canBypassOwnership: boolean;
  canBypassBusinessHours: boolean;
}> = {
  viewer: {
    canBypassOwnership: false,
    canBypassBusinessHours: false,
  },
  editor: {
    canBypassOwnership: false,
    canBypassBusinessHours: false,
  },
  admin: {
    canBypassOwnership: true,
    canBypassBusinessHours: false, // Even admins must respect business hours
  },
};

/**
 * Evaluate an ABAC attribute across ALL roles the user has
 * Returns true if ANY role permits the attribute
 */
function evaluateAttribute(
  roles: Role[],
  attribute: keyof typeof ABAC_POLICY[Role]
): boolean {
  return roles.some(role => {
    const policy = ABAC_POLICY[role];
    return policy ? policy[attribute] : false;
  });
}

// Business hours: 09:00-17:00 America/Toronto
function isWithinBusinessHours(date: Date): boolean {
  // Use Intl.DateTimeFormat to reliably get the hour in Toronto timezone
  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone: 'America/Toronto',
    hour: 'numeric',
    hour12: false,
  });
  const hourStr = formatter.format(date);
  const hour = parseInt(hourStr, 10);
  return hour >= 9 && hour < 17;
}

export function createAbacMiddleware(reportStore: ReportStore) {
  return (options: AbacOptions) => {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const authContext = req.authContext;

      if (!authContext) {
        res.status(401).json({ error: 'No auth context' });
        return;
      }

      // Evaluate ABAC policies against ALL roles the user has
      const canBypassOwnership = evaluateAttribute(authContext.roles, 'canBypassOwnership');
      const canBypassBusinessHours = evaluateAttribute(authContext.roles, 'canBypassBusinessHours');

      // Check business hours for write operations
      if (options.checkBusinessHours) {
        const now = getNow();
        if (!isWithinBusinessHours(now) && !canBypassBusinessHours) {
          res.status(403).json({ error: 'Operation not allowed outside business hours' });
          return;
        }
      }

      // Check ownership for resource-specific operations
      if (options.checkOwnership && req.params.id) {
        const report = await reportStore.getById(req.params.id);

        if (!report) {
          res.status(404).json({ error: 'Report not found' });
          return;
        }

        // Check if user owns resource OR has a role that can bypass ownership
        const isOwner = report.ownerId === authContext.sub;
        if (!isOwner && !canBypassOwnership) {
          res.status(403).json({ error: 'Not authorized to modify this resource' });
          return;
        }
      }

      next();
    };
  };
}
