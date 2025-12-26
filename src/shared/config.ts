// Parse CORS origins from environment variable (comma-separated)
function parseCorsOrigins(): string[] {
  const origins = process.env.CORS_ALLOWED_ORIGINS;
  if (!origins) {
    // Default to empty in production, test origins in test mode
    return process.env.NODE_ENV === 'test'
      ? ['http://localhost:3000', 'http://localhost:8080', 'https://trusted.example.com']
      : [];
  }
  return origins.split(',').map(o => o.trim()).filter(Boolean);
}

export const config = {
  gateway: {
    port: parseInt(process.env.PORT || '3000', 10),
    jwtSecret: process.env.JWT_SECRET || 'test-secret-key-for-external-tokens',
    internalJwtSecret: process.env.INTERNAL_JWT_SECRET || 'test-secret-key-for-internal-tokens',
    jwtIssuer: 'auth-gauntlet',
    jwtAudience: 'auth-gauntlet-api',
    downstreamUrl: process.env.DOWNSTREAM_URL || 'http://localhost:3001',
    redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
    // CORS: Explicit allowlist - never use '*' with credentials
    corsAllowedOrigins: parseCorsOrigins(),
  },
  downstream: {
    port: parseInt(process.env.PORT || '3001', 10),
    internalJwtSecret: process.env.INTERNAL_JWT_SECRET || 'test-secret-key-for-internal-tokens',
    internalJwtIssuer: 'gateway',
    internalJwtAudience: 'downstream',
  },
  isTest: process.env.NODE_ENV === 'test',
};
