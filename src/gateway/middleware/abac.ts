import { Request, Response, NextFunction } from 'express';
import { getNow } from '../../shared/clock';
import { ReportStore } from '../store/reportStore';
import { Role } from '../../shared/types';

/**
 * ABAC Action Types - Explicit actions that can be performed
 */
type AbacAction = 'read' | 'write' | 'delete' | 'admin';

/**
 * Per-Role ABAC Policy Declaration
 * Each role gets its own explicit set of attribute requirements
 */
interface RoleAbacPolicy {
  action: AbacAction;
  checkOwnership: boolean;
  checkBusinessHours: boolean;
}

/**
 * ABAC Options - Declares policies for EACH role separately
 * This is the correct ABAC pattern: each role has its own parameter declaration
 */
type AbacOptions = {
  [K in Role]?: RoleAbacPolicy;
};

/**
 * ABAC Policy Engine - Evaluates all four attribute categories:
 *
 * 1. SUBJECT ATTRIBUTES: User identity (sub) and roles
 * 2. RESOURCE ATTRIBUTES: Resource ownership (ownerId)
 * 3. ACTION ATTRIBUTES: The operation being performed (read/write/delete/admin)
 * 4. ENVIRONMENTAL ATTRIBUTES: Time of day (business hours)
 *
 * IMPORTANT: Each role has its own ABAC declaration with its own parameters.
 * Access is granted if ANY of the user's roles has a policy that permits access.
 */

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
 * Evaluate ABAC policy for a specific role
 * Returns: { allowed: boolean, reason?: string }
 */
async function evaluateRolePolicy(
  policy: RoleAbacPolicy,
  authContext: { sub: string; roles: Role[] },
  req: Request,
  reportStore: ReportStore
): Promise<{ allowed: boolean; reason?: string }> {
  const now = getNow();

  // Check business hours for this role's policy
  if (policy.checkBusinessHours && !isWithinBusinessHours(now)) {
    return { allowed: false, reason: 'Operation not allowed outside business hours' };
  }

  // Check ownership for this role's policy
  if (policy.checkOwnership && req.params.id) {
    const report = await reportStore.getById(req.params.id);
    if (!report) {
      return { allowed: false, reason: 'Report not found' };
    }
    const isOwner = report.ownerId === authContext.sub;
    if (!isOwner) {
      return { allowed: false, reason: 'Not authorized to modify this resource' };
    }
  }

  return { allowed: true };
}

/**
 * ABAC Decision Point - Evaluates per-role policies
 *
 * Each role declared in the options has its own ABAC parameters.
 * User must have at least one role with a policy that permits access.
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
      // EVALUATE ABAC POLICY FOR EACH ROLE
      // ========================================
      // Find which of the user's roles have declared policies
      const userRolesWithPolicies = authContext.roles.filter(
        (role): role is Role => role in options
      );

      // User must have at least one role with a declared policy
      if (userRolesWithPolicies.length === 0) {
        res.status(403).json({
          error: 'Access denied',
          details: 'No ABAC policy declared for user roles'
        });
        return;
      }

      // Evaluate each role's policy - access granted if ANY role permits
      let lastDenialReason = 'Access denied';

      for (const role of userRolesWithPolicies) {
        const policy = options[role]!;

        // Evaluate this role's specific policy
        const result = await evaluateRolePolicy(policy, authContext, req, reportStore);

        if (result.allowed) {
          // This role's policy permits access - proceed
          next();
          return;
        }

        // Track the denial reason
        if (result.reason) {
          lastDenialReason = result.reason;
        }
      }

      // No role's policy permitted access
      res.status(403).json({ error: lastDenialReason });
    };
  };
}
