import { AuthContext } from '../shared/types';

interface CallCounts {
  reportUpdate: number;
  reindex: number;
}

interface LastIdentity {
  sub: string | null;
  roles: string[] | null;
  sessionId: string | null;
}

class CallCounter {
  private counts: CallCounts = {
    reportUpdate: 0,
    reindex: 0,
  };

  private lastIdentity: LastIdentity = {
    sub: null,
    roles: null,
    sessionId: null,
  };

  increment(operation: keyof CallCounts): void {
    this.counts[operation]++;
  }

  getCounts(): CallCounts {
    return { ...this.counts };
  }

  reset(): void {
    this.counts = {
      reportUpdate: 0,
      reindex: 0,
    };
    this.lastIdentity = {
      sub: null,
      roles: null,
      sessionId: null,
    };
  }

  recordIdentity(context: AuthContext): void {
    this.lastIdentity = {
      sub: context.sub,
      roles: [...context.roles],
      sessionId: context.sessionId,
    };
  }

  getLastIdentity(): LastIdentity {
    return { ...this.lastIdentity };
  }
}

export const callCounter = new CallCounter();
