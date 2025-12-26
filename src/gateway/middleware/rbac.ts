import { Request, Response, NextFunction } from 'express';
import { Role } from '../../shared/types';

export function createRbacMiddleware() {
  return (allowedRoles: Role[]) => {
    return (req: Request, res: Response, next: NextFunction): void => {
      const authContext = req.authContext;

      if (!authContext) {
        res.status(401).json({ error: 'No auth context' });
        return;
      }

      const hasRole = authContext.roles.some(role => allowedRoles.includes(role));

      if (!hasRole) {
        res.status(403).json({ error: 'Insufficient role permissions' });
        return;
      }

      next();
    };
  };
}
