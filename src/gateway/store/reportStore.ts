import { v4 as uuidv4 } from 'uuid';
import { Report } from '../../shared/types';

export interface ReportStore {
  getById(id: string): Promise<Report | null>;
  create(data: { ownerId: string; title: string }): Promise<Report>;
  reset(): void;
  seed(reports: Report[]): void;
}

class InMemoryReportStore implements ReportStore {
  private reports: Map<string, Report> = new Map();

  async getById(id: string): Promise<Report | null> {
    return this.reports.get(id) || null;
  }

  async create(data: { ownerId: string; title: string }): Promise<Report> {
    const report: Report = {
      id: uuidv4(),
      ownerId: data.ownerId,
      title: data.title,
    };
    this.reports.set(report.id, report);
    return report;
  }

  reset(): void {
    this.reports.clear();
  }

  seed(reports: Report[]): void {
    this.reset();
    for (const report of reports) {
      this.reports.set(report.id, report);
    }
  }
}

// Export singleton instance
export const reportStore: ReportStore = new InMemoryReportStore();
