export type Role = 'viewer' | 'editor' | 'admin';

export interface ExternalTokenPayload {
  sub: string;
  roles: Role[];
  iss: string;
  aud: string;
  exp: number;
  iat: number;
  jti: string;
  sid: string; // session id
}

export interface InternalTokenPayload {
  sub: string;
  roles: Role[];
  sessionId: string;
  jti: string;
  iss: string;
  aud: string;
  exp: number;
  iat: number;
}

export interface Session {
  id: string;
  userId: string;
  roles: Role[]; // Roles are immutable for session lifetime - prevents escalation
  refreshToken: string;
  expiresAt: number; // Unix timestamp
  revoked: boolean;
  createdAt: number;
}

export interface Report {
  id: string;
  ownerId: string;
  title: string;
}

export interface AuthContext {
  sub: string;
  roles: Role[];
  sessionId: string;
  jti: string;
}

// Route permission configuration
export interface RoutePermission {
  method: string;
  path: string | RegExp;
  requiredRoles: Role[];
  isWrite: boolean;
  callsDownstream: boolean;
  checkOwnership?: boolean; // for ABAC
}
