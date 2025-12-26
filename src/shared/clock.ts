import { config } from './config';

let testNow: Date | null = null;

export function setTestNow(date: Date | null): void {
  if (config.isTest) {
    testNow = date;
  }
}

export function getNow(): Date {
  if (config.isTest && testNow) {
    return testNow;
  }
  return new Date();
}

export function parseTestNowHeader(header: string | undefined): void {
  if (config.isTest && header) {
    // Check if it's purely numeric (timestamp in milliseconds)
    if (/^\d+$/.test(header)) {
      testNow = new Date(parseInt(header, 10));
    } else {
      // Try parsing as ISO string
      const parsed = new Date(header);
      if (!isNaN(parsed.getTime())) {
        testNow = parsed;
      }
    }
  }
}
