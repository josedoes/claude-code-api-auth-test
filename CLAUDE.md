# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

A test-driven "auth gauntlet" demonstrating JWT + RBAC + ABAC + session management across two services. Success = all integration tests pass.

## Architecture

Two HTTP services communicating locally:
- **gateway** (port 3000): Public-facing, handles ingress auth/authz, calls downstream via egress client
- **downstream** (port 3001): Internal service, requires verified identity from gateway, exposes `GET /__calls` for test assertions

State store: Redis (docker) for sessions; in-memory fallback only for local dev (tests must use Redis).

## Tech Stack

- Node.js + TypeScript
- Express for HTTP
- `jose` for JWT operations
- Jest + Supertest for integration tests
- Redis for session storage
- Docker Compose for local orchestration

## Commands

```bash
# Start services (redis + gateway + downstream)
docker-compose up -d

# Run all tests
npm test

# Run single test file
npm test -- --testPathPattern=<pattern>

# Run tests matching description
npm test -- -t "<test name>"
```

## Security Pipeline (Gateway)

All protected routes flow through:
1. **Authenticate**: JWT verification (signature, iss, aud, exp, reject alg=none) + session validity check
2. **Authorize RBAC**: Check `roles` claim against route requirements
3. **Authorize ABAC**: Check ownership + business hours (09:00-17:00 America/Toronto)
4. **Execute**: Handler runs, may call downstream

## Egress Authorization

The egress client MUST enforce authorization BEFORE calling downstream:
- Deny fast on RBAC/ABAC failure (downstream never called)
- On allow: create short-lived internal JWT with verified identity (`sub`, `roles`, `sessionId`, `jti`)
- Never trust client-supplied headers for identity

## JWT Claims

External access token:
- `sub`: user id
- `roles`: string[] (viewer/editor/admin)
- `iss`, `aud`, `exp`: standard claims
- `jti`: unique token id (required for session revocation)
- `sid`: session id (required for session management)

Internal service token (gateway → downstream):
- Derived from verified external token
- Short-lived, signed with internal key

## RBAC Policy

- **viewer**: read-only (`GET /reports/*`)
- **editor**: read + write (non-admin routes)
- **admin**: all routes

## ABAC Policy

Write operations allowed if:
- (role=admin OR report.ownerId == sub) AND within business hours

## Session Management

- Refresh tokens rotate (single-use)
- Logout revokes session immediately
- Access tokens rejected if session revoked/expired (session state overrides JWT exp)
- Session TTL can be shorter than JWT exp

## Test Fixtures

Users: `userA` (viewer/editor), `userB`, `admin1`
Reports: `r1` (ownerId=userA), `r2` (ownerId=userB)

## Time Control

Inject clock provider; accept `X-Test-Now` header only when `NODE_ENV=test`.

## Key Test Assertions

Every "deny" test for downstream-triggering routes must verify:
1. Response is 401 or 403
2. Downstream `/__calls` count did NOT increase

## Endpoints

Gateway:
- `GET /health` - public
- `GET /reports/:id` - read (protected)
- `POST /reports` - write (protected)
- `POST /reports/:id/update` - write, calls downstream (protected)
- `POST /admin/reindex` - admin, calls downstream (protected)
- `POST /auth/refresh` - refresh flow
- `POST /auth/logout` - logout flow

Downstream:
- `POST /internal/report/:id/update` - internal auth required
- `POST /internal/reindex` - internal auth required
- `GET /__calls` - test-only call counter
