import { Request, Response, NextFunction } from 'express';
import { getNow } from '../../shared/clock';
import { ReportStore } from '../store/reportStore';
import { Role } from '../../shared/types';

/**
 * ABAC Action Types - Explicit actions that can be performed
 */
type AbacAction = 'read' | 'write' | 'delete' | 'admin';

interface AbacOptions {
  action: AbacAction;
  checkOwnership?: boolean;
  checkBusinessHours?: boolean;
}

/**
 * ABAC Policy Engine - Evaluates all four attribute categories:
 *
 * 1. SUBJECT ATTRIBUTES: User identity (sub) and roles
 * 2. RESOURCE ATTRIBUTES: Resource ownership (ownerId)
 * 3. ACTION ATTRIBUTES: The operation being performed (read/write/delete/admin)
 * 4. ENVIRONMENTAL ATTRIBUTES: Time of day (business hours)
 *
 * Policy evaluation combines all attributes to make access decisions.
 * Access is granted if ANY of the user's roles permits the action.
 */

/**
 * Role-Action Permission Matrix
 * Defines which actions each role can perform
 */
const ROLE_ACTION_PERMISSIONS: Record<Role, Set<AbacAction>> = {
  viewer: new Set(['read']),
  editor: new Set(['read', 'write']),
  admin: new Set(['read', 'write', 'delete', 'admin']),
};

/**
 * Role-Attribute Policy Matrix
 * Defines attribute-based capabilities for each role
 */
const ROLE_ATTRIBUTE_POLICY: Record<Role, {
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
 * Evaluate if ANY of the user's roles permits the action
 */
function canPerformAction(roles: Role[], action: AbacAction): boolean {
  return roles.some(role => {
    const permissions = ROLE_ACTION_PERMISSIONS[role];
    return permissions ? permissions.has(action) : false;
  });
}

/**
 * Evaluate an ABAC attribute across ALL roles the user has
 * Returns true if ANY role permits the attribute
 */
function evaluateAttribute(
  roles: Role[],
  attribute: keyof typeof ROLE_ATTRIBUTE_POLICY[Role]
): boolean {
  return roles.some(role => {
    const policy = ROLE_ATTRIBUTE_POLICY[role];
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

/**
 * ABAC Decision Point - Evaluates all four attribute categories
 */
export function createAbacMiddleware(reportStore: ReportStore) {
  return (options: AbacOptions) => {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const authContext = req.authContext;

      if (!authContext) {
        res.status(401).json({ error: 'No auth context' });
        return;
      }

      // ========================================
      // 1. ACTION ATTRIBUTE CHECK
      // ========================================
      // Verify the user's roles permit this action type
      if (!canPerformAction(authContext.roles, options.action)) {
        res.status(403).json({
          error: 'Action not permitted',
          details: `Action '${options.action}' requires appropriate role`
        });
        return;
      }

      // ========================================
      // 2. ENVIRONMENTAL ATTRIBUTE CHECK
      // ========================================
      // Evaluate ABAC policies against ALL roles the user has
      const canBypassBusinessHours = evaluateAttribute(authContext.roles, 'canBypassBusinessHours');

      if (options.checkBusinessHours) {
        const now = getNow();
        if (!isWithinBusinessHours(now) && !canBypassBusinessHours) {
          res.status(403).json({ error: 'Operation not allowed outside business hours' });
          return;
        }
      }

      // ========================================
      // 3. RESOURCE ATTRIBUTE CHECK
      // ========================================
      const canBypassOwnership = evaluateAttribute(authContext.roles, 'canBypassOwnership');

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

      // All ABAC checks passed
      next();
    };
  };
}
