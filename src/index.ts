/**
 * nest-authify
 * Complete authentication and authorization package for NestJS
 */

// Module
export * from './auth.module';

// Services
export * from './services/base-auth.service';
export * from './services/auth.service';
export * from './services/hash.service';

// Controllers
export * from './controllers/auth.controller';
export * from './controllers/oauth.controller';

// Interfaces
export * from './interfaces/auth-options.interface';
export * from './interfaces/auth-repository.interface';
export * from './interfaces/session-store.interface';

// DTOs
export * from './dto/auth.dto';

// Strategies
export * from './strategies/jwt.strategy';
export * from './strategies/local.strategy';
export * from './strategies/google.strategy';
export * from './strategies/facebook.strategy';
export * from './strategies/github.strategy';

// Guards
export * from './guards/jwt-auth.guard';
export * from './guards/local-auth.guard';
export * from './guards/roles.guard';
export * from './guards/permissions.guard';
export * from './guards/google-auth.guard';
export * from './guards/facebook-auth.guard';
export * from './guards/github-auth.guard';

// Decorators
export * from './decorators/auth.decorator';
export * from './decorators/public.decorator';
export * from './decorators/roles.decorator';
export * from './decorators/permissions.decorator';
export * from './decorators/current-user.decorator';
export * from './decorators/session-id.decorator';
export * from './decorators/get-request.decorator';
export * from './decorators/ip-address.decorator';
export * from './decorators/user-agent.decorator';

// Session Stores
export * from './session/memory-session.store';
export * from './session/redis-session.store';

// Constants
export * from './constants';