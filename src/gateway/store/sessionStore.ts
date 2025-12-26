import Redis from 'ioredis';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../../shared/config';
import { Session } from '../../shared/types';
import { getNow } from '../../shared/clock';

export interface SessionStore {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  create(userId: string, ttlMs: number): Promise<{ session: Session; refreshToken: string }>;
  getById(sessionId: string): Promise<Session | null>;
  getByRefreshToken(refreshToken: string): Promise<Session | null>;
  rotateRefreshToken(sessionId: string): Promise<string | null>;
  revoke(sessionId: string): Promise<boolean>;
  markRefreshTokenUsed(refreshToken: string): Promise<boolean>;
  isRefreshTokenUsed(refreshToken: string): Promise<boolean>;
}

class InMemorySessionStore implements SessionStore {
  private sessions: Map<string, Session> = new Map();
  private refreshTokenToSession: Map<string, string> = new Map();
  private usedRefreshTokens: Set<string> = new Set();
  private lockMap: Map<string, boolean> = new Map();

  async connect(): Promise<void> {
    // No-op for in-memory store
  }

  async disconnect(): Promise<void> {
    this.sessions.clear();
    this.refreshTokenToSession.clear();
    this.usedRefreshTokens.clear();
    this.lockMap.clear();
  }

  async create(userId: string, ttlMs: number): Promise<{ session: Session; refreshToken: string }> {
    const sessionId = uuidv4();
    const refreshToken = uuidv4();
    const now = getNow().getTime();

    const session: Session = {
      id: sessionId,
      userId,
      refreshToken,
      expiresAt: now + ttlMs,
      revoked: false,
      createdAt: now,
    };

    this.sessions.set(sessionId, session);
    this.refreshTokenToSession.set(refreshToken, sessionId);

    return { session, refreshToken };
  }

  async getById(sessionId: string): Promise<Session | null> {
    return this.sessions.get(sessionId) || null;
  }

  async getByRefreshToken(refreshToken: string): Promise<Session | null> {
    const sessionId = this.refreshTokenToSession.get(refreshToken);
    if (!sessionId) return null;
    return this.getById(sessionId);
  }

  async rotateRefreshToken(sessionId: string): Promise<string | null> {
    const session = this.sessions.get(sessionId);
    if (!session || session.revoked) return null;

    const now = getNow().getTime();
    if (session.expiresAt < now) return null;

    // Delete old refresh token mapping
    this.refreshTokenToSession.delete(session.refreshToken);

    // Create new refresh token
    const newRefreshToken = uuidv4();

    // Update session with new refresh token
    session.refreshToken = newRefreshToken;
    this.sessions.set(sessionId, session);

    // Create new refresh token mapping
    this.refreshTokenToSession.set(newRefreshToken, sessionId);

    return newRefreshToken;
  }

  async revoke(sessionId: string): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    if (!session) return false;

    // Mark session as revoked
    session.revoked = true;
    this.sessions.set(sessionId, session);

    // Delete refresh token mapping
    this.refreshTokenToSession.delete(session.refreshToken);

    return true;
  }

  async markRefreshTokenUsed(refreshToken: string): Promise<boolean> {
    // Simulate atomic SETNX behavior
    if (this.usedRefreshTokens.has(refreshToken)) {
      return false; // Already used
    }

    // Check for lock (race condition simulation)
    const lockKey = `lock:${refreshToken}`;
    if (this.lockMap.get(lockKey)) {
      return false;
    }

    this.lockMap.set(lockKey, true);
    this.usedRefreshTokens.add(refreshToken);
    return true; // First use
  }

  async isRefreshTokenUsed(refreshToken: string): Promise<boolean> {
    return this.usedRefreshTokens.has(refreshToken);
  }
}

class RedisSessionStore implements SessionStore {
  private client: Redis | null = null;

  async connect(): Promise<void> {
    this.client = new Redis(config.gateway.redisUrl, {
      maxRetriesPerRequest: 3,
      retryStrategy: (times) => {
        if (times > 3) return null;
        return Math.min(times * 100, 1000);
      },
    });

    await this.client.ping();
  }

  async disconnect(): Promise<void> {
    if (this.client) {
      await this.client.quit();
      this.client = null;
    }
  }

  async create(userId: string, ttlMs: number): Promise<{ session: Session; refreshToken: string }> {
    if (!this.client) throw new Error('Redis not connected');

    const sessionId = uuidv4();
    const refreshToken = uuidv4();
    const now = getNow().getTime();

    const session: Session = {
      id: sessionId,
      userId,
      refreshToken,
      expiresAt: now + ttlMs,
      revoked: false,
      createdAt: now,
    };

    await this.client.set(
      `session:${sessionId}`,
      JSON.stringify(session),
      'PX',
      ttlMs
    );

    await this.client.set(
      `refresh:${refreshToken}`,
      sessionId,
      'PX',
      ttlMs
    );

    return { session, refreshToken };
  }

  async getById(sessionId: string): Promise<Session | null> {
    if (!this.client) throw new Error('Redis not connected');

    const data = await this.client.get(`session:${sessionId}`);
    if (!data) return null;

    return JSON.parse(data) as Session;
  }

  async getByRefreshToken(refreshToken: string): Promise<Session | null> {
    if (!this.client) throw new Error('Redis not connected');

    const sessionId = await this.client.get(`refresh:${refreshToken}`);
    if (!sessionId) return null;

    return this.getById(sessionId);
  }

  async rotateRefreshToken(sessionId: string): Promise<string | null> {
    if (!this.client) throw new Error('Redis not connected');

    const session = await this.getById(sessionId);
    if (!session || session.revoked) return null;

    const now = getNow().getTime();
    if (session.expiresAt < now) return null;

    // Delete old refresh token mapping
    await this.client.del(`refresh:${session.refreshToken}`);

    // Create new refresh token
    const newRefreshToken = uuidv4();
    const remainingTtl = session.expiresAt - now;

    // Update session with new refresh token
    session.refreshToken = newRefreshToken;
    await this.client.set(
      `session:${sessionId}`,
      JSON.stringify(session),
      'PX',
      remainingTtl
    );

    // Create new refresh token mapping
    await this.client.set(
      `refresh:${newRefreshToken}`,
      sessionId,
      'PX',
      remainingTtl
    );

    return newRefreshToken;
  }

  async revoke(sessionId: string): Promise<boolean> {
    if (!this.client) throw new Error('Redis not connected');

    const session = await this.getById(sessionId);
    if (!session) return false;

    // Mark session as revoked
    session.revoked = true;

    // Keep the session record but mark it revoked
    const now = getNow().getTime();
    const remainingTtl = Math.max(session.expiresAt - now, 1000);

    await this.client.set(
      `session:${sessionId}`,
      JSON.stringify(session),
      'PX',
      remainingTtl
    );

    // Delete refresh token mapping
    await this.client.del(`refresh:${session.refreshToken}`);

    return true;
  }

  async markRefreshTokenUsed(refreshToken: string): Promise<boolean> {
    if (!this.client) throw new Error('Redis not connected');

    // Use SETNX to atomically mark as used (returns 1 if set, 0 if already exists)
    const result = await this.client.setnx(`used:${refreshToken}`, '1');
    if (result === 1) {
      // Set expiry on the used marker
      await this.client.expire(`used:${refreshToken}`, 3600); // 1 hour
      return true; // First use
    }
    return false; // Already used
  }

  async isRefreshTokenUsed(refreshToken: string): Promise<boolean> {
    if (!this.client) throw new Error('Redis not connected');

    const result = await this.client.exists(`used:${refreshToken}`);
    return result === 1;
  }
}

// Create the appropriate store based on environment
function createSessionStore(): SessionStore {
  // Always use in-memory for tests to avoid Redis dependency
  if (config.isTest) {
    return new InMemorySessionStore();
  }
  return new RedisSessionStore();
}

// Export singleton instance
export const sessionStore: SessionStore = createSessionStore();
