import * as jose from 'jose';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../shared/config';
import { Role } from '../shared/types';

const secret = new TextEncoder().encode(config.gateway.jwtSecret);

export interface TokenOptions {
  sub?: string;
  roles?: Role[];
  sid?: string;
  jti?: string;
  iss?: string;
  aud?: string;
  exp?: number;
  iat?: number;
}

export async function createTestToken(options: TokenOptions = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  const payload: Record<string, unknown> = {
    sub: options.sub ?? 'userA',
    roles: options.roles ?? ['viewer'],
    sid: options.sid ?? uuidv4(),
    jti: options.jti ?? uuidv4(),
  };

  const token = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt(options.iat ?? now)
    .setExpirationTime(options.exp ?? now + 3600)
    .setIssuer(options.iss ?? config.gateway.jwtIssuer)
    .setAudience(options.aud ?? config.gateway.jwtAudience)
    .sign(secret);

  return token;
}

export async function createTokenWithWrongSignature(options: TokenOptions = {}): Promise<string> {
  const wrongSecret = new TextEncoder().encode('wrong-secret-key');
  const now = Math.floor(Date.now() / 1000);

  const payload: Record<string, unknown> = {
    sub: options.sub ?? 'userA',
    roles: options.roles ?? ['viewer'],
    sid: options.sid ?? uuidv4(),
    jti: options.jti ?? uuidv4(),
  };

  const token = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt(options.iat ?? now)
    .setExpirationTime(options.exp ?? now + 3600)
    .setIssuer(options.iss ?? config.gateway.jwtIssuer)
    .setAudience(options.aud ?? config.gateway.jwtAudience)
    .sign(wrongSecret);

  return token;
}

export function createAlgNoneToken(options: TokenOptions = {}): string {
  const now = Math.floor(Date.now() / 1000);

  const header = { alg: 'none', typ: 'JWT' };
  const payload = {
    sub: options.sub ?? 'userA',
    roles: options.roles ?? ['admin'],
    sid: options.sid ?? uuidv4(),
    jti: options.jti ?? uuidv4(),
    iss: options.iss ?? config.gateway.jwtIssuer,
    aud: options.aud ?? config.gateway.jwtAudience,
    iat: options.iat ?? now,
    exp: options.exp ?? now + 3600,
  };

  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');

  return `${encodedHeader}.${encodedPayload}.`;
}

export async function createExpiredToken(options: TokenOptions = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  const payload: Record<string, unknown> = {
    sub: options.sub ?? 'userA',
    roles: options.roles ?? ['viewer'],
    sid: options.sid ?? uuidv4(),
    jti: options.jti ?? uuidv4(),
  };

  const token = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt(now - 7200) // 2 hours ago
    .setExpirationTime(now - 3600) // expired 1 hour ago
    .setIssuer(options.iss ?? config.gateway.jwtIssuer)
    .setAudience(options.aud ?? config.gateway.jwtAudience)
    .sign(secret);

  return token;
}

// Helper to get Toronto time for business hours testing
export function getTorontoBusinessHoursTime(): Date {
  // Create a date at 10:00 AM Toronto time
  const date = new Date();
  // Set to a known business hour in Toronto
  date.setUTCHours(15, 0, 0, 0); // 15:00 UTC = 10:00 or 11:00 Toronto depending on DST
  return date;
}

export function getTorontoOutsideBusinessHoursTime(): Date {
  // Create a date at 8:00 PM Toronto time
  const date = new Date();
  // Set to outside business hours in Toronto
  date.setUTCHours(1, 0, 0, 0); // 01:00 UTC = 20:00 or 21:00 Toronto depending on DST
  return date;
}
