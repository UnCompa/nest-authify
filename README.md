# 🔐 @nestjs-auth-validation

A complete, production-ready authentication and authorization package for NestJS applications. Supports both monolithic and microservices architectures with OAuth, JWT, Redis sessions, and more.

[![npm version](https://badge.fury.io/js/%40tu-org%2Fnestjs-auth.svg)](https://www.npmjs.com/package/nest-auth-kit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ Features

- 🔑 **Multiple Authentication Strategies**: Local (username/password), JWT, OAuth (Google, Facebook, GitHub)
- 🏢 **Flexible Architecture**: Works in monolithic and microservices setups
- 🔄 **Session Management**: Optional Redis-backed sessions with revocation support
- 🎯 **Easy to Use**: Unified `@Auth()` decorator for authentication and authorization
- 🛡️ **Type-Safe**: Full TypeScript support
- 🔧 **Extensible**: Base classes for custom implementations
- 📦 **Plug & Play**: Default implementations for quick setup
- 🚀 **Production Ready**: Built-in guards, decorators, and best practices

## 📦 Installation

```bash
npm install nest-auth-kit
# or
yarn add nest-auth-kit
# or
pnpm add nest-auth-kit
```

### Peer Dependencies

```bash
npm install @nestjs/common @nestjs/core @nestjs/jwt @nestjs/passport passport passport-jwt passport-local bcrypt
```

### Optional Dependencies

For OAuth support:

```bash
npm install passport-google-oauth20 passport-facebook passport-github2
```

For Redis sessions:

```bash
npm install ioredis
```

## 🚀 Quick Start

### 1. Basic Setup (Local Authentication + JWT)

```typescript
// app.module.ts
import { Module } from '@nestjs/common';
import { AuthModule } from 'nest-auth-kit';
import { UserRepository } from './repositories/user.repository';

@Module({
  imports: [
    AuthModule.forRoot({
      mode: 'monolith',
      jwtSecret: process.env.JWT_SECRET,
      jwtExpiresIn: '1h',
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

### 2. Create Auth Controller

```typescript
// auth.controller.ts
import { Controller, Post, Body, UseGuards, Get } from '@nestjs/common';
import { LocalAuthGuard, Auth, Public, CurrentUser } from 'nest-auth-kit';

@Controller('auth')
export class AuthController {
  constructor(
    @Inject('AUTH_SERVICE') private authService: any,
  ) {}

  @Public()
  @Post('login')
  @UseGuards(LocalAuthGuard)
  async login(@CurrentUser() user: any) {
    return this.authService.createSession(user);
  }

  @Auth()
  @Get('profile')
  async getProfile(@CurrentUser() user: any) {
    return user;
  }
}
```

### 3. Protect Your Routes

```typescript
// users.controller.ts
import { Controller, Get } from '@nestjs/common';
import { Auth, Roles, CurrentUser } from 'nest-auth-kit';

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
}
```

## 📖 Documentation

### Configuration Options

#### AuthModuleOptions

```typescript
interface AuthModuleOptions {
  // Basic configuration
  jwtSecret: string;                    // JWT secret key
  jwtExpiresIn?: string;               // Access token expiration (default: '60m')
  refreshExpiresIn?: string;           // Refresh token expiration (default: '7d')
  
  // Architecture mode
  mode: 'monolith' | 'microservice-server' | 'microservice-client';
  
  // Session store (optional)
  sessionStore?: {
    type: 'redis' | 'memory';
    redis?: {
      host: string;
      port: number;
      password?: string;
      db?: number;
      keyPrefix?: string;
    };
  };
  
  // Custom service/repository
  authService?: any;                   // Custom auth service class
  authRepository?: any;                // Repository implementation
  
  // OAuth configuration
  google?: {
    clientId: string;
    clientSecret: string;
    callbackUrl?: string;
  };
  facebook?: {
    clientId: string;
    clientSecret: string;
    callbackUrl?: string;
  };
  github?: {
    clientId: string;
    clientSecret: string;
    callbackUrl?: string;
  };
  
  // Strategies to enable
  strategies?: {
    local?: boolean;
    jwt?: boolean;
    google?: boolean;
    facebook?: boolean;
    github?: boolean;
  };
}
```

### Repository Interface

Implement `IAuthRepository` for your data source:

```typescript
import { IAuthRepository } from 'nest-auth-kit';
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';

@Injectable()
export class UserRepository implements IAuthRepository {
  constructor(
    @InjectRepository(User)
    private userRepo: Repository<User>,
  ) {}

  async findUserByUsername(username: string) {
    return this.userRepo.findOne({ where: { username } });
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

## 🎯 Usage Examples

### With Redis Sessions

```typescript
@Module({
  imports: [
    AuthModule.forRoot({
      mode: 'monolith',
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
  ],
})
export class AppModule {}
```

### With OAuth (Google, Facebook, GitHub)

```typescript
// app.module.ts
@Module({
  imports: [
    AuthModule.forRoot({
      mode: 'monolith',
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
  ],
})
export class AppModule {}

// oauth.controller.ts
import { Controller, Get, UseGuards, Res } from '@nestjs/common';
import { GoogleAuthGuard, CurrentUser, Public } from 'nest-auth-kit';

@Controller('auth')
export class OAuthController {
  constructor(
    @Inject('AUTH_SERVICE') private authService: any,
  ) {}

  @Public()
  @Get('google')
  @UseGuards(GoogleAuthGuard)
  async googleAuth() {}

  @Public()
  @Get('google/callback')
  @UseGuards(GoogleAuthGuard)
  async googleAuthCallback(@CurrentUser() user: any, @Res() res: Response) {
    const session = await this.authService.createSession(user, {
      provider: 'google',
    });
    
    return res.redirect(
      `${process.env.FRONTEND_URL}/auth/callback?token=${session.accessToken}`
    );
  }
}
```

### Custom Auth Service

Extend `BaseAuthService` for custom logic:

```typescript
import { Injectable } from '@nestjs/common';
import { BaseAuthService } from 'nest-auth-kit';
import * as bcrypt from 'bcrypt';

@Injectable()
export class CustomAuthService extends BaseAuthService {
  constructor(
    jwtService: JwtService,
    sessionStore: ISessionStore,
    private usersService: UsersService,
    private logService: LogService,
  ) {
    super(jwtService, sessionStore);
  }

  // Override to add logging
  async createSession(user: any, options?: any) {
    await this.logService.info(`User login: ${user.id}`);
    return super.createSession(user, options);
  }

  // Implement validation with rate limiting
  async validateUser(username: string, password: string) {
    const user = await this.usersService.findByUsername(username);
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return null;
    }
    
    const { password: _, ...result } = user;
    return result;
  }

  protected async getUserById(userId: string) {
    return this.usersService.findById(userId);
  }

  // Add custom methods
  async changePassword(userId: string, oldPassword: string, newPassword: string) {
    const user = await this.usersService.findById(userId);
    
    if (!(await bcrypt.compare(oldPassword, user.password))) {
      throw new Error('Invalid old password');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.usersService.update(userId, { password: hashedPassword });

    // Revoke all user sessions
    await this.revokeAllUserSessions(userId);
  }
}

// Use in module
@Module({
  imports: [
    AuthModule.forRoot({
      mode: 'monolith',
      jwtSecret: process.env.JWT_SECRET,
      authService: CustomAuthService, // Your custom service
      strategies: {
        local: true,
        jwt: true,
      },
    }),
  ],
})
export class AppModule {}
```

### Session Management

```typescript
import { Controller, Post, Get } from '@nestjs/common';
import { Auth, SessionId, CurrentUser } from 'nest-auth-kit';

@Controller('session')
@Auth()
export class SessionController {
  constructor(
    @Inject('AUTH_SERVICE') private authService: any,
  ) {}

  @Post('logout')
  async logout(@SessionId() sessionId: string) {
    await this.authService.revokeSession(sessionId);
    return { message: 'Logged out successfully' };
  }

  @Post('logout-all')
  async logoutAll(@CurrentUser('userId') userId: string) {
    await this.authService.revokeAllUserSessions(userId);
    return { message: 'All sessions revoked' };
  }
}
```

## 🎨 Decorators

### @Auth()

Unified decorator for authentication and authorization:

```typescript
// Public route (no authentication)
@Auth({ public: true })
@Get('public')
getPublic() {}

// Authenticated users only
@Auth()
@Get('protected')
getProtected() {}

// Specific roles required
@Auth({ roles: ['admin'] })
@Get('admin')
adminOnly() {}

// Multiple roles
@Auth({ roles: ['admin', 'moderator'] })
@Get('moderation')
moderation() {}

// With custom guards
@Auth({ guards: [ThrottlerGuard] })
@Post('create')
create() {}

// Complex authorization
@Auth({ 
  roles: ['admin'], 
  permissions: ['posts:delete'],
  guards: [CustomAuditGuard]
})
@Delete(':id')
delete() {}
```

### @Public()

Shorthand for public routes:

```typescript
@Public()
@Get('health')
healthCheck() {
  return { status: 'ok' };
}
```

### @Roles()

Shorthand for role-based authorization:

```typescript
@Roles('admin', 'moderator')
@Get('admin')
adminRoute() {}
```

### @CurrentUser()

Extract user from request:

```typescript
// Get entire user object
@Get('profile')
getProfile(@CurrentUser() user: any) {
  return user;
}

// Get specific property
@Get('id')
getUserId(@CurrentUser('userId') userId: string) {
  return { userId };
}
```

### @SessionId()

Extract session ID from JWT:

```typescript
@Post('logout')
async logout(@SessionId() sessionId: string) {
  await this.authService.revokeSession(sessionId);
}
```

## 🔒 Guards

All guards are automatically configured and exported:

- `JwtAuthGuard` - JWT authentication
- `RolesGuard` - Role-based authorization
- `LocalAuthGuard` - Local username/password
- `GoogleAuthGuard` - Google OAuth
- `FacebookAuthGuard` - Facebook OAuth
- `GithubAuthGuard` - GitHub OAuth

```typescript
// Manual guard usage
@UseGuards(JwtAuthGuard, RolesGuard)
@Get('protected')
protectedRoute() {}

// With OAuth
@UseGuards(GoogleAuthGuard)
@Get('google')
googleAuth() {}
```

## 🏗️ Microservices Architecture

### Authentication Microservice (Server)

```typescript
// main.ts
import { NestFactory } from '@nestjs/core';
import { Transport } from '@nestjs/microservices';

async function bootstrap() {
  const app = await NestFactory.createMicroservice(AppModule, {
    transport: Transport.TCP,
    options: {
      host: '0.0.0.0',
      port: 3001,
    },
  });
  await app.listen();
}
bootstrap();

// app.module.ts
@Module({
  imports: [
    AuthModule.forRoot({
      mode: 'microservice-server',
      jwtSecret: process.env.JWT_SECRET,
      authRepository: UserRepository,
    }),
  ],
})
export class AppModule {}
```

### Client Microservice

```typescript
// orders.module.ts
import { Module } from '@nestjs/common';
import { AuthModule } from 'nest-auth-kit';
import { Transport } from '@nestjs/microservices';

@Module({
  imports: [
    AuthModule.forRoot({
      mode: 'microservice-client',
      jwtSecret: process.env.JWT_SECRET,
      microserviceOptions: {
        transport: Transport.TCP,
        options: {
          host: 'auth-service',
          port: 3001,
        },
      },
    }),
  ],
})
export class OrdersModule {}

// orders.controller.ts
import { Controller, Get, UseGuards } from '@nestjs/common';
import { MicroserviceJwtAuthGuard, CurrentUser } from 'nest-auth-kit';

@Controller('orders')
@UseGuards(MicroserviceJwtAuthGuard)
export class OrdersController {
  @Get()
  async getOrders(@CurrentUser() user: any) {
    return `Orders for user ${user.userId}`;
  }
}
```

## 📝 API Reference

### BaseAuthService

Core methods available when extending `BaseAuthService`:

```typescript
class BaseAuthService {
  // Create JWT access token
  createJwt(user: any, expiresIn?: string, sessionId?: string): Promise<string>
  
  // Create refresh token
  createRefreshToken(user: any, expiresIn?: string, sessionId?: string): Promise<string>
  
  // Create complete session
  createSession(user: any, options?: any): Promise<AuthSession>
  
  // Verify and decode token
  verifyToken(token: string): Promise<JwtPayload>
  
  // Refresh access token
  refreshAccessToken(refreshToken: string): Promise<{ accessToken: string }>
  
  // Revoke specific session
  revokeSession(sessionId: string): Promise<void>
  
  // Revoke all user sessions
  revokeAllUserSessions(userId: string): Promise<void>
  
  // Must implement
  protected abstract getUserById(userId: string): Promise<any>
}
```

### IAuthRepository

Interface to implement for data persistence:

```typescript
interface IAuthRepository {
  findUserByUsername(username: string): Promise<any>
  findUserById(id: string): Promise<any>
  findUserByProviderId(provider: string, providerId: string): Promise<any>
  createUser(data: any): Promise<any>
  updateUser(id: string, data: any): Promise<any>
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
}
```

## 🧪 Testing

Example test setup:

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { JwtModule } from '@nestjs/jwt';
import { AuthModule } from 'nest-auth-kit';

describe('AuthService', () => {
  let service: any;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        JwtModule.register({
          secret: 'test-secret',
        }),
        AuthModule.forRoot({
          mode: 'monolith',
          jwtSecret: 'test-secret',
          authRepository: MockUserRepository,
          strategies: {
            local: true,
            jwt: true,
          },
        }),
      ],
    }).compile();

    service = module.get('AUTH_SERVICE');
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

## 🔧 Environment Variables

```env
# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRES_IN=60m
REFRESH_EXPIRES_IN=7d

# Redis (optional)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password

# Google OAuth (optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Facebook OAuth (optional)
FACEBOOK_APP_ID=your-facebook-app-id
FACEBOOK_APP_SECRET=your-facebook-app-secret

# GitHub OAuth (optional)
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Frontend URL (for OAuth callbacks)
FRONTEND_URL=http://localhost:4200
```

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [NestJS](https://nestjs.com/)
- Authentication strategies powered by [Passport](http://www.passportjs.org/)
- JWT handling by [@nestjs/jwt](https://github.com/nestjs/jwt)

## 📞 Support

- 📧 Email: <uncompadev@gmail.com>
- 🐛 Issues: [GitHub Issues](https://github.com/UnCompa/nest-auth-kit/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/UnCompa/nest-auth-kit/discussions)

## 🗺️ Roadmap

- [ ] Add support for more OAuth providers (Apple, LinkedIn, Twitter)
- [ ] Implement permission-based authorization system
- [ ] Add support for RBAC (Role-Based Access Control)
- [ ] GraphQL integration
- [ ] WebSocket authentication support
- [ ] Two-Factor Authentication (2FA)
- [ ] Magic link authentication
- [ ] Rate limiting integration
- [ ] Audit logging
- [ ] Admin dashboard for session management

---

Made with ❤️ by [UnCompa](https://portafolio.uncompa.dev)
