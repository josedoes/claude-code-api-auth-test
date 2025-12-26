# Auth Gauntlet: JWT + RBAC + ABAC + Session Management

A test-driven implementation proving Claude Code can one-shot build a complete API authentication/authorization system.

## 🎯 The Challenge

From a LinkedIn debate:
> "By about the third ask. Start with JWT, ask it to add RBAC to ingress and egress, then add ABAC to ingress and egress. At this point it starts to break down. Then add session management associated with JWT and it just breaks entirely. It really can only add JWT"

**Result:** All 40 integration tests pass in a single implementation.

## ⏱️ Implementation Metrics

| Metric | Value |
|--------|-------|
| **Total Implementation Time** | ~10 minutes |
| **Lines of TypeScript** | 1,991 |
| **Source Files** | 17 |
| **Integration Tests** | 40 |
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
- Signature verification (HS256)
- Issuer and audience validation
- Expiration checking
- **alg=none rejection** (critical security)

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
- Refresh token rotation (single-use)
- Immediate logout revocation
- Session TTL can be shorter than JWT expiry
- Race condition safe (atomic token marking)

## 🧪 Test Coverage

| Category | Tests | Description |
|----------|-------|-------------|
| A) Public Routes | 1 | Health check without auth |
| B) JWT Auth | 8 | Missing/malformed/invalid/expired tokens, alg=none |
| C) RBAC Ingress | 5 | Role-based route access |
| D) RBAC Egress | 3 | Downstream not called on deny |
| E) ABAC Ingress | 5 | Ownership + business hours |
| F) ABAC Egress | 4 | Verify identity propagation, no spoofing |
| G) Session Mgmt | 9 | Refresh rotation, logout, TTL, concurrency |
| H) Downstream Protection | 2 | Direct access denied, forged tokens rejected |
| I) Invariants | 3 | No 500s, side-effect free denials |

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
│   │   ├── auth.ts      # JWT verification
│   │   ├── session.ts   # Session validity check
│   │   ├── rbac.ts      # Role-based access
│   │   └── abac.ts      # Attribute-based access
│   ├── egress/
│   │   └── client.ts    # Internal JWT signing
│   ├── store/
│   │   ├── sessionStore.ts  # Redis/in-memory
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
│   ├── config.ts        # Environment config
│   └── clock.ts         # Time control for tests
└── tests/
    ├── integration.test.ts  # All 40 tests
    └── helpers.ts       # Token generation utils
```

## 🤖 Generated With

[Claude Code](https://claude.ai/code) - Anthropic's CLI for Claude

This entire implementation was generated in a single session with Claude Opus 4.5, demonstrating that LLMs can handle complex, multi-layered security implementations when given clear specifications.
