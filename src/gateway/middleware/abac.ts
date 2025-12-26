import { Request, Response, NextFunction } from 'express';
import { getNow } from '../../shared/clock';
import { ReportStore } from '../store/reportStore';

interface AbacOptions {
  checkOwnership?: boolean;
  checkBusinessHours?: boolean;
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

      const isAdmin = authContext.roles.includes('admin');

      // Check business hours for write operations
      if (options.checkBusinessHours) {
        const now = getNow();
        if (!isWithinBusinessHours(now)) {
          // Even admins cannot write outside business hours
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

        // Admin can bypass ownership check
        if (!isAdmin && report.ownerId !== authContext.sub) {
          res.status(403).json({ error: 'Not authorized to modify this resource' });
          return;
        }
      }

      next();
    };
  };
}
