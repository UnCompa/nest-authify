# 🔐 nest-authify

Complete, production-ready authentication and authorization package for NestJS applications. Supports monolithic and microservices architectures with OAuth, JWT, Redis sessions, and more.

[![npm version](https://badge.fury.io/js/nest-authify.svg)](https://badge.fury.io/js/nest-authify)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ Features

- 🔑 **Multiple Authentication Strategies**: Local (username/password), JWT, OAuth (Google, Facebook, GitHub)
- 🏢 **Flexible Architecture**: Works in monolithic and microservices setups
- 🔄 **Session Management**: Optional Redis-backed sessions with revocation support
- 🎯 **Easy to Use**: Unified `@Auth()` decorator for authentication and authorization
- 🛡️ **Type-Safe**: Full TypeScript support with comprehensive types
- 🔧 **Extensible**: Base classes for custom implementations
- 📦 **Plug & Play**: Default implementations for quick setup
- 🚀 **Production Ready**: Built-in guards, decorators, and best practices
- 💾 **Flexible Storage**: Memory or Redis session storage
- 📝 **Swagger Integration**: Automatic API documentation
- 🎨 **Customizable**: Custom hash functions, repositories, and services

## 📦 Installation

```bash
npm install nest-authify
# or
yarn add nest-authify
# or
pnpm add nest-authify
```

### Required Peer Dependencies

```bash
npm install @nestjs/common @nestjs/core @nestjs/jwt @nestjs/passport @nestjs/config passport passport-jwt passport-local bcrypt joi uuid
```

### Optional Dependencies

For Redis sessions:

```bash
npm install ioredis
```

For OAuth support:

```bash
# Google
npm install passport-google-oauth20

# Facebook
npm install passport-facebook

# GitHub
npm install passport-github2
```

## 🚀 Quick Start

### 1. Basic Setup (Normal Mode)

```typescript
// app.module.ts
import { Module } from '@nestjs/common';
import { AuthModule } from 'nest-authify';
import { UserRepository } from './repositories/user.repository';

@Module({
  imports: [
    AuthModule.forRoot({
      mode: 'normal', // Para aplicaciones monolíticas
      jwtSecret: process.env.JWT_SECRET,
      jwtExpiresIn: '60m',
      refreshExpiresIn: '7d',
      authRepository: UserRepository,
      strategies: {
        local: true,
        jwt: true,
      },
    }),
  ],
})
export class AppModule {}
```

### 2. Implement Auth Repository

```typescript
// user.repository.ts
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { IAuthRepository } from 'nest-authify';
import { User } from './entities/user.entity';

@Injectable()
export class UserRepository implements IAuthRepository {
  constructor(
    @InjectRepository(User)
    private userRepo: Repository<User>,
  ) {}

  async findUserByUsername(username: string) {
    return this.userRepo.findOne({
      where: [{ username }, { email: username }],
    });
  }

  async findUserById(id: string) {
    return this.userRepo.findOne({ where: { id } });
  }

  async findUserByProviderId(provider: string, providerId: string) {
    return this.userRepo.findOne({ where: { provider, providerId } });
  }

  async createUser(data: any) {
    const user = this.userRepo.create(data);
    return this.userRepo.save(user);
  }

  async updateUser(id: string, data: any) {
    await this.userRepo.update(id, data);
    return this.findUserById(id);
  }
}
```

### 3. Use Built-in Controllers

The package provides ready-to-use controllers:

```typescript
// No need to create controllers!
// These endpoints are automatically available:

// POST /auth/register
// POST /auth/login
// GET  /auth/profile
// POST /auth/refresh
// POST /auth/logout
// POST /auth/logout-all
// GET  /auth/verify
// POST /auth/change-password
```

### 4. Use @Auth() Decorator

```typescript
// users.controller.ts
import { Controller, Get } from '@nestjs/common';
import { Auth, CurrentUser } from 'nest-authify';

@Controller('users')
export class UsersController {
  // Public route
  @Auth({ public: true })
  @Get('public')
  getPublic() {
    return 'This is public';
  }

  // Authenticated users only
  @Auth()
  @Get('profile')
  getProfile(@CurrentUser() user: any) {
    return user;
  }

  // Admin only
  @Auth({ roles: ['admin'] })
  @Get('admin')
  adminOnly() {
    return 'Admin only content';
  }

  // Multiple roles
  @Auth({ roles: ['admin', 'moderator'] })
  @Get('moderation')
  moderation() {
    return 'Moderation panel';
  }

  // Permissions-based
  @Auth({ permissions: ['posts:delete'] })
  @Delete('posts/:id')
  deletePost() {
    return 'Post deleted';
  }
}
```

## 📖 Configuration Options

### AuthModuleOptions

```typescript
interface AuthModuleOptions {
  // Modo de operación
  mode: 'normal' | 'server' | 'client';

  // Configuración JWT
  jwtSecret: string;
  jwtExpiresIn?: string; // default: '60m'
  refreshExpiresIn?: string; // default: '7d'

  // Session Store (opcional)
  sessionStore?: {
    type: 'memory' | 'redis';
    redis?: {
      host: string;
      port: number;
      password?: string;
      db?: number;
      keyPrefix?: string;
    };
  };

  // Servicios personalizados
  authService?: Type<any>; // Debe extender BaseAuthService
  authRepository?: Type<any>; // Debe implementar IAuthRepository

  // Hash personalizado
  hashCallback?: (password: string) => Promise<string>;
  hashVerifyCallback?: (password: string, hash: string) => Promise<boolean>;

  // OAuth
  google?: {
    clientId: string;
    clientSecret: string;
    callbackUrl?: string;
    scope?: string[];
  };
  facebook?: {
    clientId: string;
    clientSecret: string;
    callbackUrl?: string;
    scope?: string[];
  };
  github?: {
    clientId: string;
    clientSecret: string;
    callbackUrl?: string;
    scope?: string[];
  };

  // Estrategias
  strategies?: {
    local?: boolean;
    jwt?: boolean;
    google?: boolean;
    facebook?: boolean;
    github?: boolean;
  };

  // Controladores
  enableControllers?: boolean; // default: true
  controllersPrefix?: string; // default: 'auth'
  enableSwagger?: boolean; // default: true
}
```

## 🔧 Advanced Usage

### Custom Hash Function

```typescript
import * as argon2 from 'argon2';

AuthModule.forRoot({
  // ... otras opciones
  hashCallback: async (password: string) => {
    return argon2.hash(password);
  },
  hashVerifyCallback: async (password: string, hash: string) => {
    return argon2.verify(hash, password);
  },
}),
```

### Redis Session Store

```typescript
AuthModule.forRoot({
  mode: 'normal',
  jwtSecret: process.env.JWT_SECRET,
  authRepository: UserRepository,
  sessionStore: {
    type: 'redis',
    redis: {
      host: 'localhost',
      port: 6379,
      password: process.env.REDIS_PASSWORD,
      keyPrefix: 'auth:',
    },
  },
  strategies: {
    local: true,
    jwt: true,
  },
}),
```

### OAuth Configuration

```typescript
AuthModule.forRoot({
  mode: 'normal',
  jwtSecret: process.env.JWT_SECRET,
  authRepository: UserRepository,
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackUrl: 'http://localhost:3000/auth/google/callback',
  },
  facebook: {
    clientId: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackUrl: 'http://localhost:3000/auth/facebook/callback',
  },
  github: {
    clientId: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackUrl: 'http://localhost:3000/auth/github/callback',
  },
  strategies: {
    local: true,
    jwt: true,
    google: true,
    facebook: true,
    github: true,
  },
}),
```

OAuth endpoints are automatically available:

- `GET /auth/google` - Inicia flujo OAuth
- `GET /auth/google/callback` - Callback de Google
- `GET /auth/facebook` - Inicia flujo OAuth
- `GET /auth/facebook/callback` - Callback de Facebook
- `GET /auth/github` - Inicia flujo OAuth
- `GET /auth/github/callback` - Callback de GitHub

### Custom Auth Service

```typescript
import { Injectable } from '@nestjs/common';
import { BaseAuthService } from 'nest-authify';

@Injectable()
export class CustomAuthService extends BaseAuthService {
  // Override para añadir logging
  async createSession(user: any, options?: any) {
    console.log(`User login: ${user.id}`);
    return super.createSession(user, options);
  }

  // Implementación requerida
  protected async getUserById(userId: string) {
    return this.repository.findUserById(userId);
  }

  // Métodos personalizados
  async sendWelcomeEmail(userId: string) {
    // Tu lógica aquí
  }
}

// Usar en el módulo
AuthModule.forRoot({
  // ... otras opciones
  authService: CustomAuthService,
}),
```

### Extending AuthSession

```typescript
// Extender la interfaz AuthSession
declare module 'nest-authify' {
  interface AuthSession {
    ipAddress?: string;
    userAgent?: string;
    deviceId?: string;
  }
}

// Usar en el servicio
const session = await this.authService.createSession(user, {
  metadata: {
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
    deviceId: req.headers['x-device-id'],
  },
});
```

## 🏗️ Architecture Modes

### Normal Mode (Monolithic)

Complete authentication in a single application.

```typescript
AuthModule.forRoot({
  mode: 'normal',
  jwtSecret: process.env.JWT_SECRET,
  authRepository: UserRepository,
  strategies: { local: true, jwt: true },
})
```

### Server Mode (Microservice Auth Server)

Dedicated authentication microservice.

```typescript
// auth-service/app.module.ts
AuthModule.forRoot({
  mode: 'server',
  jwtSecret: process.env.JWT_SECRET,
  authRepository: UserRepository,
  strategies: { local: true, jwt: true },
})
```

### Client Mode (Microservice Client)

Services that consume authentication.

```typescript
// orders-service/app.module.ts
AuthModule.forRoot({
  mode: 'client',
  jwtSecret: process.env.JWT_SECRET, // Same secret as auth server
  strategies: { jwt: true }, // Only JWT validation needed
})
```

## 🎯 Decorators

### @Auth()

Unified decorator for authentication and authorization.

```typescript
// Public route
@Auth({ public: true })
@Get('public')
getPublic() {}

// Requires authentication
@Auth()
@Get('protected')
getProtected() {}

// Requires specific roles
@Auth({ roles: ['admin'] })
@Get('admin')
adminOnly() {}

// Requires permissions
@Auth({ permissions: ['posts:write'] })
@Post('posts')
createPost() {}

// Combined with custom guards
@Auth({ 
  roles: ['admin'], 
  permissions: ['users:delete'],
  guards: [ThrottlerGuard]
})
@Delete('users/:id')
deleteUser() {}
```

### @CurrentUser()

Extracts user from request.

```typescript
@Get('profile')
getProfile(@CurrentUser() user: any) {
  return user;
}

// Extract specific property
@Get('id')
getUserId(@CurrentUser('id') userId: string) {
  return { userId };
}
```

### @SessionId()

Extracts session ID from JWT.

```typescript
@Post('logout')
async logout(@SessionId() sessionId: string) {
  await this.authService.revokeSession(sessionId);
}
```

### Other Decorators

```typescript
@IpAddress() // Get client IP
@UserAgent() // Get User-Agent
@GetRequest() // Get full request object
```

## 🛡️ Guards

All guards are exported and can be used manually:

```typescript
import { 
  JwtAuthGuard, 
  RolesGuard, 
  LocalAuthGuard,
  GoogleAuthGuard,
  FacebookAuthGuard,
  GithubAuthGuard,
  PermissionsGuard 
} from 'nest-authify';

@UseGuards(JwtAuthGuard, RolesGuard)
@Get('protected')
protectedRoute() {}
```

## 📝 Environment Variables

Create a `.env` file:

```env
# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRES_IN=60m
REFRESH_EXPIRES_IN=7d

# Redis (optional)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password
REDIS_DB=0
REDIS_KEY_PREFIX=auth:

# Google OAuth (optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback

# Facebook OAuth (optional)
FACEBOOK_APP_ID=your-facebook-app-id
FACEBOOK_APP_SECRET=your-facebook-app-secret
FACEBOOK_CALLBACK_URL=http://localhost:3000/auth/facebook/callback

# GitHub OAuth (optional)
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_CALLBACK_URL=http://localhost:3000/auth/github/callback

# Frontend URL (for OAuth redirects)
FRONTEND_URL=http://localhost:4200
```

## 🔌 Async Configuration

For dynamic configuration:

```typescript
import { ConfigService } from '@nestjs/config';

AuthModule.forRootAsync({
  imports: [ConfigModule],
  useFactory: async (configService: ConfigService) => ({
    mode: 'normal',
    jwtSecret: configService.get('JWT_SECRET'),
    jwtExpiresIn: configService.get('JWT_EXPIRES_IN', '60m'),
    refreshExpiresIn: configService.get('REFRESH_EXPIRES_IN', '7d'),
    authRepository: UserRepository,
    sessionStore: configService.get('REDIS_HOST') ? {
      type: 'redis',
      redis: {
        host: configService.get('REDIS_HOST'),
        port: configService.get('REDIS_PORT'),
        password: configService.get('REDIS_PASSWORD'),
      },
    } : undefined,
    strategies: {
      local: true,
      jwt: true,
      google: !!configService.get('GOOGLE_CLIENT_ID'),
      facebook: !!configService.get('FACEBOOK_APP_ID'),
      github: !!configService.get('GITHUB_CLIENT_ID'),
    },
  }),
  inject: [ConfigService],
}),
```

## 📚 API Reference

### BaseAuthService

Base service that can be extended:

```typescript
class BaseAuthService {
  // JWT Methods
  createJwt(user: any, expiresIn?: string, sessionId?: string): Promise<string>
  createRefreshToken(user: any, expiresIn?: string, sessionId?: string): Promise<string>
  verifyToken(token: string): Promise<JwtPayload>
  
  // Session Methods
  createSession(user: any, options?: CreateSessionOptions): Promise<AuthSession>
  refreshAccessToken(refreshToken: string): Promise<{ accessToken: string; expiresIn: number }>
  revokeSession(sessionId: string): Promise<void>
  revokeAllUserSessions(userId: string): Promise<void>
  
  // User Methods
  register(data: RegisterUserDto): Promise<any>
  validateUser(username: string, password: string): Promise<ValidatedUser | null>
  validateOAuthUser(provider: string, providerId: string, profile: any): Promise<any>
  changePassword(userId: string, oldPassword: string, newPassword: string): Promise<void>
  
  // Abstract Methods (must implement)
  protected abstract getUserById(userId: string): Promise<any>
}
```

### IAuthRepository

Interface to implement for your data layer:

```typescript
interface IAuthRepository {
  findUserByUsername(username: string): Promise<any>
  findUserById(id: string): Promise<any>
  findUserByProviderId(provider: string, providerId: string): Promise<any>
  createUser(data: any): Promise<any>
  updateUser(id: string, data: any): Promise<any>
  deleteUser?(id: string): Promise<void>
  findUsersByRole?(role: string): Promise<any[]>
  findActiveUsers?(): Promise<any[]>
}
```

### ISessionStore

Interface for custom session stores:

```typescript
interface ISessionStore {
  set(key: string, value: any, ttl?: number): Promise<void>
  get(key: string): Promise<any>
  delete(key: string): Promise<void>
  exists(key: string): Promise<boolean>
  keys(pattern?: string): Promise<string[]>
  clear(): Promise<void>
}
```

## 🧪 Testing

Example test setup:

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { AuthModule, AUTH_SERVICE } from 'nest-authify';

describe('AuthService', () => {
  let service: any;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        AuthModule.forRoot({
          mode: 'normal',
          jwtSecret: 'test-secret',
          authRepository: MockUserRepository,
          strategies: { local: true, jwt: true },
        }),
      ],
    }).compile();

    service = module.get(AUTH_SERVICE);
  });

  it('should create a session', async () => {
    const user = { id: '123', roles: ['user'] };
    const session = await service.createSession(user);
    
    expect(session).toHaveProperty('accessToken');
    expect(session).toHaveProperty('refreshToken');
    expect(session.sub).toBe('123');
  });
});
```

## 📊 Swagger Integration

The package automatically integrates with Swagger:

```typescript
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

// In main.ts
const config = new DocumentBuilder()
  .setTitle('API Documentation')
  .setDescription('API with nest-authify')
  .setVersion('1.0')
  .addBearerAuth() // Add this for JWT
  .build();

const document = SwaggerModule.createDocument(app, config);
SwaggerModule.setup('api', app, document);
```

All auth endpoints are automatically documented with:

- Request/Response DTOs
- Authentication requirements
- Error responses
- Example values

## 🔒 Security Best Practices

1. **Strong JWT Secrets**: Use long, random strings
2. **Short Token Expiration**: Keep access tokens short-lived (15-60 minutes)
3. **Refresh Token Rotation**: Implement refresh token rotation for better security
4. **HTTPS Only**: Always use HTTPS in production
5. **Rate Limiting**: Implement rate limiting on auth endpoints
6. **Password Strength**: Validate password strength on registration
7. **Session Revocation**: Implement session revocation for logout
8. **Audit Logging**: Log authentication events

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [NestJS](https://nestjs.com/)
- Authentication powered by [Passport](http://www.passportjs.org/)
- JWT handling by [@nestjs/jwt](https://github.com/nestjs/jwt)

## 📧 Support

- 📧 Email: <uncompadev@gmail.com>
- 🐛 Issues: [GitHub Issues](https://github.com/UnCompa/nest-authify/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/UnCompa/nest-authify/discussions)

## 🗺️ Roadmap

- [ ] Support for more OAuth providers (Apple, LinkedIn, Twitter)
- [ ] Permission-based authorization system (CASL integration)
- [ ] Two-Factor Authentication (2FA)
- [ ] Magic link authentication
- [ ] WebSocket authentication support
- [ ] GraphQL integration
- [ ] Rate limiting integration
- [ ] Audit logging
- [ ] Admin dashboard for session management
- [ ] Multi-tenancy support
- [ ] Biometric authentication support

---

Made with ❤️ by [UnCompa](https://portafolio.uncompa.dev)
