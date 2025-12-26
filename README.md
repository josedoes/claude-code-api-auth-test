# Auth Gauntlet: JWT + RBAC + ABAC + Session Management + CORS

A test-driven implementation proving Claude Code can build a complete, security-hardened API authentication/authorization system.

## 🎯 The Challenge

From a LinkedIn debate:
> "By about the third ask. Start with JWT, ask it to add RBAC to ingress and egress, then add ABAC to ingress and egress. At this point it starts to break down. Then add session management associated with JWT and it just breaks entirely. It really can only add JWT"

**Result:** All 55 integration tests pass with production-grade security.

## ⏱️ Implementation Metrics

| Metric | Value |
|--------|-------|
| **Lines of TypeScript** | ~2,500 |
| **Source Files** | 18 |
| **Integration Tests** | 55 |
| **Test Pass Rate** | 100% |

### Timeline
- `17:04:48` - Started (CLAUDE.md with spec)
- `17:14:22` - Complete implementation with all tests passing

### Code Breakdown
| Component | Lines |
|-----------|-------|
| Integration Tests | 676 |
| Session Store (Redis + In-Memory) | 291 |
| Gateway Routes & Middleware | 462 |
| Downstream Service | 177 |
| Shared Types & Utils | 104 |
| Test Helpers | 119 |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Gateway (port 3000)                     │
├─────────────────────────────────────────────────────────────┤
│  Request → JWT Auth → Session Check → RBAC → ABAC → Handler │
│                                                    ↓         │
│                                              Egress Client   │
│                                         (signs internal JWT) │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Downstream (port 3001)                    │
├─────────────────────────────────────────────────────────────┤
│  Internal JWT Auth → Handler → Call Counter (for testing)   │
└─────────────────────────────────────────────────────────────┘
```

## 🔐 Security Features

### JWT Authentication
- Signature verification (HS256 only)
- Pre-verification algorithm check (rejects `alg=none` BEFORE verification)
- Issuer and audience validation
- Expiration checking
- Required claims validation (`sub`, `roles`, `jti`, `sid`)

### RBAC (Role-Based Access Control)
- **viewer**: read-only access
- **editor**: read + write (non-admin)
- **admin**: full access
- Enforced on both ingress AND egress

### ABAC (Attribute-Based Access Control)
- Ownership verification (user can only modify own resources)
- Business hours enforcement (09:00-17:00 America/Toronto)
- Admin can bypass ownership (not business hours)

### Session Management
- **Roles stored in session** - prevents privilege escalation on refresh
- Refresh token rotation (single-use, atomic)
- Immediate logout revocation
- Session TTL can override JWT expiry
- Race condition safe (Redis SETNX)

### CORS Security
- Explicit origin allowlist (no wildcards with credentials)
- Null origin rejection
- Preflight caching with `Access-Control-Max-Age`
- `Vary: Origin` header for cache correctness
- Strict method and header allowlists

## 🧪 Test Coverage

| Category | Tests | Description |
|----------|-------|-------------|
| A) Public Routes | 1 | Health check without auth |
| B) JWT Auth | 8 | Missing/malformed/invalid/expired tokens, alg=none |
| C) RBAC Ingress | 5 | Role-based route access |
| D) RBAC Egress | 3 | Downstream not called on deny |
| E) ABAC Ingress | 5 | Ownership + business hours |
| F) ABAC Egress | 4 | Verify identity propagation, no spoofing |
| G) Session Mgmt | 11 | Refresh rotation, logout, TTL, concurrency, **privilege escalation prevention** |
| H) Downstream Protection | 2 | Direct access denied, forged tokens rejected |
| I) CORS Security | 6 | Preflight, origin validation, null rejection, side-effect prevention |
| J) Invariants | 3 | No 500s, side-effect free denials |
| K) Security Hardening | 7 | Algorithm rejection (HS384/RS256), missing claims, downstream claims |

## 🛡️ Security Hardening

Key security measures implemented:

1. **Privilege Escalation Prevention**: Roles are stored immutably in the session at creation time. The refresh endpoint ignores any client-provided roles in the request body.

2. **Algorithm Confusion Prevention**: JWT algorithm is validated BEFORE signature verification. Only HS256 is accepted; `alg=none`, `HS384`, `RS256` etc. are explicitly rejected.

3. **Explicit Egress Authorization**: The egress client has its own policy map and enforces authorization BEFORE making downstream calls—defense-in-depth against forgotten middleware.

4. **Atomic Token Operations**: Refresh token single-use is enforced via atomic Redis SETNX, preventing race conditions in concurrent refresh attempts.

5. **Defense in Depth**: Both gateway and downstream services independently validate JWTs with required claims validation.

6. **No Trust in Client Headers**: User identity is derived exclusively from verified JWT claims, never from spoofable headers like `X-User` or `X-Roles`.

7. **CORS Side-Effect Prevention**: Disallowed origins receive 403 for ALL request types, not just preflights—preventing any server-side effects from hostile origins.

## 🚀 Quick Start

```bash
# Install dependencies
npm install

# Run tests (uses in-memory session store)
npm test

# Run with Docker (uses Redis)
docker-compose up -d
```

## 📁 Project Structure

```
src/
├── gateway/
│   ├── middleware/
│   │   ├── auth.ts      # JWT verification + alg check
│   │   ├── session.ts   # Session validity check
│   │   ├── rbac.ts      # Role-based access
│   │   ├── abac.ts      # Attribute-based access
│   │   └── cors.ts      # CORS origin validation
│   ├── egress/
│   │   └── client.ts    # Internal JWT signing
│   ├── store/
│   │   ├── sessionStore.ts  # Redis/in-memory (roles stored here)
│   │   └── reportStore.ts   # In-memory reports
│   └── routes/
│       └── auth.ts      # Refresh/logout endpoints
├── downstream/
│   ├── middleware/
│   │   └── internalAuth.ts  # Internal JWT verification
│   ├── callCounter.ts   # Test assertion helper
│   └── index.ts
├── shared/
│   ├── types.ts         # Shared type definitions
│   ├── config.ts        # Environment config + CORS origins
│   └── clock.ts         # Time control for tests
└── tests/
    ├── integration.test.ts  # All 48 tests
    └── helpers.ts       # Token generation utils
```

## 🤖 Generated With

[Claude Code](https://claude.ai/code) - Anthropic's CLI for Claude

This entire implementation was generated in a single session with Claude Opus 4.5, demonstrating that LLMs can handle complex, multi-layered security implementations when given clear specifications.
