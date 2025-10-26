# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-15

### Added

- Initial release
- Local authentication strategy (username/password)
- JWT authentication strategy
- OAuth strategies (Google, Facebook, GitHub)
- Redis session store support
- In-memory session store
- Unified `@Auth()` decorator
- Guards: JwtAuthGuard, RolesGuard, LocalAuthGuard, OAuth guards
- Decorators: @CurrentUser, @SessionId, @Public, @Roles
- BaseAuthService for custom implementations
- DefaultAuthService for quick setup
- Microservices support (client and server)
- Session management (revoke, revoke all)
- Full TypeScript support
- Comprehensive documentation

### Security

- Secure JWT token generation
- Password hashing with bcrypt
- Session revocation support
- Rate limiting friendly (works with @nestjs/throttler)

## [Unreleased]

### Planned

- Two-Factor Authentication (2FA)
- Permission-based authorization
- More OAuth providers (Apple, LinkedIn, Twitter)
- Magic link authentication
- WebSocket authentication
- GraphQL integration
