export * from './core/interfaces/auth-service.interface';
export * from './core/interfaces/auth-repository.interface';
export * from './core/interfaces/session-store.interface';

// Types
export * from './core/types/auth-session.interface';

// Implementations
export * from './implementations/base-auth.service';
export * from './implementations/default-auth.service';

// Session stores
export * from './session/memory-session.store';
export * from './session/redis-session.store';

// Strategies
export * from './strategies/local.strategy';
export * from './strategies/jwt.strategy';
export * from './strategies/google.strategy';
export * from './strategies/facebook.strategy';
export * from './strategies/github.strategy';

// Guards
export * from './guards/jwt-auth.guard';
export * from './guards/roles.guard';
export * from './guards/local-auth.guard';
export * from './guards/google-auth.guard';
export * from './guards/facebook-auth.guard';
export * from './guards/github-auth.guard';

// Decorators
export * from './decorators/auth.decorator';
export * from './decorators/public.decorator';
export * from './decorators/roles.decorator';
export * from './decorators/current-user.decorator';
export * from './decorators/session-id.decorator';

// Module
export * from './auth.module';

// Microservices (si se necesita)
export * from './microservices/auth-ms-client.service';
export * from './microservices/auth-ms-server.controller';