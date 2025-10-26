import { DynamicModule, Module, Provider } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import Redis from 'ioredis';
import { FacebookAuthGuard } from './guards/facebook-auth.guard';
import { GithubAuthGuard } from './guards/github-auth.guard';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { DefaultAuthService } from './implementations/default-auth.service';
import { MemorySessionStore } from './session/memory-session.store';
import { RedisSessionStore } from './session/redis-session.store';
import { FacebookStrategy } from './strategies/facebook.strategy';
import { GithubStrategy } from './strategies/github.strategy';
import { GoogleStrategy } from './strategies/google.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { ClientProxyFactory } from '@nestjs/microservices';
import { AuthMsClientService } from './microservices/auth-ms-client.service';
import { MicroserviceJwtAuthGuard } from './guards/microservice-jwt-auth.guard';
import { AuthMsServerController } from './microservices/auth-ms-server.controller';

export interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  callbackUrl?: string;
}

export interface RedisConfig {
  host: string;
  port: number;
  password?: string;
  db?: number;
  keyPrefix?: string;
}

export interface AuthModuleOptions {
  // Configuración básica
  jwtSecret: string;
  jwtExpiresIn?: string;
  refreshExpiresIn?: string;

  // Modo: 'monolith' | 'microservice-server' | 'microservice-client'
  mode: 'monolith' | 'microservice-server' | 'microservice-client';

  // Session store (opcional)
  sessionStore?: {
    type: 'redis' | 'memory';
    redis?: RedisConfig;
  };

  // Proveedor de servicio personalizado (opcional)
  authService?: any;

  // Proveedor de repositorio (opcional)
  authRepository?: any;

  // Configuración OAuth
  google?: OAuthConfig;
  facebook?: OAuthConfig;
  github?: OAuthConfig;

  // Estrategias a habilitar
  strategies?: {
    local?: boolean;
    jwt?: boolean;
    google?: boolean;
    facebook?: boolean;
    github?: boolean;
  };

  // Configuración de microservicios
  microserviceOptions?: {
    transport: any;
    options: any;
  };
}

@Module({})
export class AuthModule {
  static forRoot(options: AuthModuleOptions): DynamicModule {
    const providers: Provider[] = [
      {
        provide: 'AUTH_CONFIG',
        useValue: options,
      },
    ];

    // === SESSION STORE ===
    if (options.sessionStore) {
      if (options.sessionStore.type === 'redis') {
        providers.push(
          {
            provide: 'REDIS_CLIENT',
            useFactory: () => {
              return new Redis({
                host: options?.sessionStore?.redis?.host,
                port: options?.sessionStore?.redis?.port,
                password: options?.sessionStore?.redis?.password,
                db: options?.sessionStore?.redis?.db || 0,
                keyPrefix: options?.sessionStore?.redis?.keyPrefix || 'auth:',
              });
            },
          },
          {
            provide: 'SESSION_STORE',
            useClass: RedisSessionStore,
          },
        );
      } else {
        providers.push({
          provide: 'SESSION_STORE',
          useClass: MemorySessionStore,
        });
      }
    }

    // === MODO MONOLITO ===
    if (options.mode === 'monolith') {
      // Servicio de autenticación
      if (options.authService) {
        providers.push({
          provide: 'AUTH_SERVICE',
          useClass: options.authService,
        });
      } else {
        providers.push({
          provide: 'AUTH_SERVICE',
          useClass: DefaultAuthService,
        });

        if (options.authRepository) {
          providers.push({
            provide: 'AUTH_REPOSITORY',
            useClass: options.authRepository,
          });
        }
      }

      // Strategies
      if (options.strategies?.local) {
        providers.push(LocalStrategy);
      }
      if (options.strategies?.jwt) {
        providers.push(JwtStrategy);
      }
      if (options.strategies?.google && options.google) {
        providers.push(GoogleStrategy);
      }
      if (options.strategies?.facebook && options.facebook) {
        providers.push(FacebookStrategy);
      }
      if (options.strategies?.github && options.github) {
        providers.push(GithubStrategy);
      }

      return {
        module: AuthModule,
        imports: [
          PassportModule.register({ defaultStrategy: 'jwt' }),
          JwtModule.register({
            secret: options.jwtSecret,
            signOptions: { expiresIn: options.jwtExpiresIn || '60m' },
          }),
        ],
        providers: [
          ...providers,
          JwtAuthGuard,
          RolesGuard,
          LocalAuthGuard,
          GoogleAuthGuard,
          FacebookAuthGuard,
          GithubAuthGuard,
        ],
        exports: [
          'AUTH_SERVICE',
          'AUTH_CONFIG',
          'SESSION_STORE',
          JwtAuthGuard,
          RolesGuard,
          LocalAuthGuard,
          GoogleAuthGuard,
          FacebookAuthGuard,
          GithubAuthGuard,
        ],
      };
    }

    // === MODO MICROSERVICIO SERVIDOR ===
    if (options.mode === 'microservice-server') {
      if (options.authService) {
        providers.push({
          provide: 'AUTH_SERVICE',
          useClass: options.authService,
        });
      } else {
        providers.push({
          provide: 'AUTH_SERVICE',
          useClass: DefaultAuthService,
        });

        if (options.authRepository) {
          providers.push({
            provide: 'AUTH_REPOSITORY',
            useClass: options.authRepository,
          });
        }
      }

      return {
        module: AuthModule,
        imports: [
          JwtModule.register({
            secret: options.jwtSecret,
            signOptions: { expiresIn: options.jwtExpiresIn || '60m' },
          }),
        ],
        controllers: [AuthMsServerController],
        providers,
        exports: ['AUTH_SERVICE', 'AUTH_CONFIG'],
      };
    }

    // === MODO MICROSERVICIO CLIENTE ===
    if (options.mode === 'microservice-client') {
      providers.push(
        {
          provide: 'AUTH_MICROSERVICE',
          useFactory: () => {
            return ClientProxyFactory.create(options.microserviceOptions);
          },
        },
        AuthMsClientService,
        MicroserviceJwtAuthGuard,
      );

      return {
        module: AuthModule,
        providers,
        exports: [AuthMsClientService, MicroserviceJwtAuthGuard, 'AUTH_CONFIG'],
      };
    }

    throw new Error('Invalid mode specified');
  }
}
