import { DynamicModule, Global, INestApplication, Module, Provider, Type } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import * as Joi from 'joi';

import { AuthController } from './controllers/auth.controller';
import { OAuthController } from './controllers/oauth.controller';
import { AuthService } from './services/auth.service';
import { BaseAuthService } from './services/base-auth.service';

// Strategies

//import { GithubStrategy } from './strategies/github.strategy';
//import { GoogleStrategy } from './strategies/google.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';

// Session Stores
import { ISessionStore } from './interfaces/session-store.interface';

// Guards
import { FacebookAuthGuard } from './guards/facebook-auth.guard';
import { GithubAuthGuard } from './guards/github-auth.guard';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { RolesGuard } from './guards/roles.guard';

import { APP_GUARD } from '@nestjs/core';
import Redis from 'ioredis';
import { AUTH_MODULE_OPTIONS, AUTH_SERVICE, FACEBOOK_STRATEGY, GITHUB_STRATEGY, GOOGLE_STRATEGY, SESSION_STORE } from './constants';
import { AuthModuleAsyncOptions, AuthModuleOptions, SessionStoreConfig } from './interfaces/auth-options.interface';
import { HashService } from './services/hash.service';
import { MemorySessionStore } from './session/memory-session.store';
import { RedisSessionStore } from './session/redis-session.store';

@Global()
@Module({})
export class AuthModule {
  /**
   * Configuración síncrona del módulo
   */
  static forRoot(options: AuthModuleOptions, app?: INestApplication): DynamicModule {
    const providers = this.createProviders(options);
    const controllers = this.createControllers(options);
    const imports = this.createImports(options);

    return {
      module: AuthModule,
      imports,
      controllers,
      providers: [
        ...providers,
        // Global guards - RolesGuard debe aplicarse globalmente si se usa @Auth()
        {
          provide: APP_GUARD,
          useClass: JwtAuthGuard,
        },
        {
          provide: APP_GUARD,
          useClass: RolesGuard,
        },
        { provide: 'NEST_APP', useValue: app },
      ],
      exports: [
        AUTH_SERVICE,
        SESSION_STORE,
        JwtModule,
        PassportModule,
        HashService,
        // Export guards para uso manual
        JwtAuthGuard,
        LocalAuthGuard,
        RolesGuard,
        GoogleAuthGuard,
        FacebookAuthGuard,
        GithubAuthGuard,
      ],
    };
  }

  /**
   * Configuración asíncrona del módulo
   */
  static forRootAsync(options: AuthModuleAsyncOptions): DynamicModule {
    const providers = this.createAsyncProviders(options);
    const controllers: any[] = []; // Se crean dinámicamente basado en opciones
    const imports = [
      ConfigModule.forRoot({
        validationSchema: this.createValidationSchema(),
        isGlobal: true,
      }),
      PassportModule.register({ defaultStrategy: 'jwt', session: false }),
      JwtModule.registerAsync({
        imports: [ConfigModule],
        useFactory: async (configService: ConfigService) => ({
          secret: configService.get<string>('JWT_SECRET'),
          signOptions: {
            expiresIn: configService.get<string>('JWT_EXPIRES_IN', '60m'),
          },
        }),
        inject: [ConfigService],
      }),
      ...(options.imports || []),
    ];

    return {
      module: AuthModule,
      imports,
      controllers,
      providers: [
        ...providers,
        {
          provide: APP_GUARD,
          useClass: JwtAuthGuard,
        },
        {
          provide: APP_GUARD,
          useClass: RolesGuard,
        },
      ],
      exports: [
        AUTH_SERVICE,
        SESSION_STORE,
        JwtModule,
        PassportModule,
        HashService,
        JwtAuthGuard,
        LocalAuthGuard,
        RolesGuard,
        GoogleAuthGuard,
        FacebookAuthGuard,
        GithubAuthGuard,
      ],
    };
  }

  /**
   * Crea los imports necesarios basados en la configuración
   */
  private static createImports(options: AuthModuleOptions): any[] {
    const imports: any[] = [
      ConfigModule.forRoot({
        validationSchema: this.createValidationSchema(),
        isGlobal: true,
      }),
      PassportModule.register({ defaultStrategy: 'jwt', session: false }),
      JwtModule.register({
        secret: options.jwtSecret,
        signOptions: {
          expiresIn: options.jwtExpiresIn || '60m',
        },
      }),
    ];

    return imports;
  }

  private static isSessionStoreConfig(
    store: SessionStoreConfig | Type<ISessionStore> | null
  ): store is SessionStoreConfig {
    return !!store && typeof store === 'object' && 'type' in store;
  }

  /**
   * Crea los providers necesarios basados en la configuración
   */
  private static createProviders(options: AuthModuleOptions): Provider[] {
    const providers: Provider[] = [
      // Opciones del módulo
      {
        provide: AUTH_MODULE_OPTIONS,
        useValue: options,
      },

      // Hash Service
      {
        provide: HashService,
        useFactory: () => {
          return new HashService(options.hashCallback);
        },
      },
      // Auth Repository
      ...(options.authRepository
        ? [
          {
            provide: 'AUTH_REPOSITORY',
            useClass: options.authRepository,
          },
        ]
        : []),
      // Auth Service
      {
        provide: AUTH_SERVICE,
        useFactory: (
          jwtService: JwtService, // ← Usa la clase JwtService
          sessionStore: ISessionStore,
          hashService: HashService,
          repository?: any,
          configService?: ConfigService,
        ) => {
          if (options.authService) {
            return new options.authService(
              jwtService,
              sessionStore,
              hashService,
              repository,
              configService,
            );
          }
          return new AuthService(
            jwtService,
            sessionStore,
            hashService,
            repository,
            configService,
          );
        },
        inject: [
          JwtService,
          SESSION_STORE,
          HashService,
          { token: 'AUTH_REPOSITORY', optional: true },
          { token: ConfigService, optional: true },
        ],
      },
    ];


    if (options.sessionStore === null) {
    } else if (typeof options.sessionStore === 'function') {
      // Custom clase (ej: new MyPrismaStore())
      providers.push({
        provide: SESSION_STORE,
        useClass: options.sessionStore as Type<ISessionStore>,
      });
    } else if (this.isSessionStoreConfig(options.sessionStore)) {
      // ✅ Memory/Redis: TS feliz
      providers.push({
        provide: SESSION_STORE,
        useFactory: (configService?: ConfigService) => {
          return this.createSessionStore(options.sessionStore as SessionStoreConfig, configService);
        },
        inject: [{ token: ConfigService, optional: true }],
      });
    }
    else {
      throw new Error('sessionStore inválido');
    }

    // Strategies
    if (options.strategies?.local) {
      providers.push(LocalStrategy);
    }
    if (options.strategies?.jwt) {
      providers.push(JwtStrategy);
    }
    // --- ESTRATEGIAS OAuth: CARGA DINÁMICA ---
    if (options.strategies?.google && options.google) {
      providers.push({
        provide: GOOGLE_STRATEGY,
        useFactory: async (authService: BaseAuthService) => {
          if (!options.strategies?.google || !options.google) {
            return null;
          }
          try {
            const { Strategy } = await import('passport-google-oauth20');
            const GoogleStrategyClass = class extends Strategy {
              constructor() {
                super(
                  {
                    clientID: options.google!.clientId,
                    clientSecret: options.google!.clientSecret,
                    callbackURL: options.google!.callbackUrl,
                    scope: ['email', 'profile'],
                  },
                  async (_: any, __: any, profile: any, done: any) => {
                    const user = await authService.validateOAuthUser('google', profile.id, profile);
                    done(null, profile);
                  },
                );
              }
            };
            const strategy = new GoogleStrategyClass();
            const passport = (await import('passport')).default;
            passport.use('google', strategy);
            return strategy;
          } catch (err) {
            console.warn('passport-google-oauth20 no instalado. Google desactivado.');
            return null;
          }
        },
        inject: [AUTH_SERVICE],
      });
    }

    if (options.strategies?.facebook && options.facebook) {
      providers.push({
        provide: FACEBOOK_STRATEGY,
        useFactory: async (authService: BaseAuthService) => {
          if (!options.strategies?.facebook || !options.facebook) {
            return null;
          }
          try {
            const { Strategy } = await import('passport-facebook');
            const FacebookStrategyClass = class extends Strategy {
              constructor() {
                super(
                  {
                    clientID: options.facebook!.clientId,
                    clientSecret: options.facebook!.clientSecret,
                    callbackURL: options.facebook!.callbackUrl || 'http://localhost:3000/auth/facebook/callback',
                    profileFields: ['id', 'emails', 'name'],
                  },
                  async (_: any, __: any, profile: any, done: any) => {
                    const user = await authService.validateOAuthUser('facebook', profile.id, {
                      email: profile.emails?.[0]?.value,
                      username: profile.emails?.[0]?.value || `fb_${profile.id}`,
                      fullName: profile.displayName,
                    });
                    done(null, profile);
                  },
                );
              }
            };
            const strategy = new FacebookStrategyClass();
            const passport = (await import('passport')).default;
            passport.use('facebook', strategy);
            return strategy;
          } catch (err) {
            console.warn('passport-facebook no instalado. Facebook desactivado.');
            return null;
          }
        },
        inject: [AUTH_SERVICE],
      });
    }

    if (options.strategies?.github && options.github) {
      providers.push({
        provide: GITHUB_STRATEGY,
        useFactory: async (authService: BaseAuthService) => {
          if (!options.strategies?.github || !options.github) {
            return null;
          }
          try {
            const { Strategy } = await import('passport-github2');
            const GithubStrategyClass = class extends Strategy {
              constructor() {
                super(
                  {
                    clientID: options.github!.clientId,
                    clientSecret: options.github!.clientSecret,
                    callbackURL: options.github!.callbackUrl,
                    scope: ['user:email']
                  },
                  async (_: any, __: any, profile: any, done: any) => {
                    const user = await authService.validateOAuthUser('github', profile.id, profile);
                    done(null, profile);
                  },
                );
              }
            };
            const strategy = new GithubStrategyClass();
            const passport = (await import('passport')).default;
            passport.use('github', strategy);
            return strategy;
          } catch (err) {
            console.warn('passport-github2 no instalado. GitHub desactivado.');
            return null;
          }
        },
        inject: [AUTH_SERVICE],
      });
    }

    // Guards
    providers.push(
      JwtAuthGuard,
      LocalAuthGuard,
      RolesGuard,
      GoogleAuthGuard,
      FacebookAuthGuard,
      GithubAuthGuard,
    );

    return providers;
  }

  /**
   * Crea providers asíncronos
   */
  private static createAsyncProviders(
    options: AuthModuleAsyncOptions,
  ): Provider[] {
    const providers: Provider[] = [
      {
        provide: AUTH_MODULE_OPTIONS,
        useFactory: options.useFactory,
        inject: options.inject || [],
      },
      {
        provide: HashService,
        useFactory: (moduleOptions: AuthModuleOptions) => {
          return new HashService(moduleOptions.hashCallback);
        },
        inject: [AUTH_MODULE_OPTIONS],
      },

      {
        provide: AUTH_SERVICE,
        useFactory: (
          moduleOptions: AuthModuleOptions,
          jwtService: JwtService, // ← Usa la clase
          sessionStore: ISessionStore,
          hashService: HashService,
          repository?: any,
          configService?: ConfigService,
        ) => {
          if (moduleOptions.authService) {
            return new moduleOptions.authService(
              jwtService,
              sessionStore,
              hashService,
              repository,
              configService,
            );
          }
          return new AuthService(
            jwtService,
            sessionStore,
            hashService,
            repository,
            configService,
          );
        },
        inject: [
          AUTH_MODULE_OPTIONS,
          JwtService,
          SESSION_STORE,
          HashService,
          { token: 'AUTH_REPOSITORY', optional: true },
          { token: ConfigService, optional: true },
        ],
      },
    ];

    providers.push({
      provide: SESSION_STORE,
      useFactory: (moduleOptions: AuthModuleOptions, configService: ConfigService) => {
        if (moduleOptions.sessionStore === null) {
          throw new Error('En modo async: provee SESSION_STORE manualmente en AppModule');
        }
        if (typeof moduleOptions.sessionStore === 'function') {
          throw new Error('Custom class no soportado en async. Provee manual en AppModule');
        }
        // Solo memory/redis en async
        return this.createSessionStore(moduleOptions.sessionStore, configService);
      },
      inject: [AUTH_MODULE_OPTIONS, ConfigService],
    });

    // Strategies y Guards se añaden dinámicamente
    providers.push(
      JwtStrategy,
      LocalStrategy,
      JwtAuthGuard,
      LocalAuthGuard,
      RolesGuard,
      GoogleAuthGuard,
      FacebookAuthGuard,
      GithubAuthGuard,
    );

    return providers;
  }

  /**
   * Crea los controladores basados en la configuración
   */
  private static createControllers(options: AuthModuleOptions): Type<any>[] {
    const controllers: Type<any>[] = [];

    // Controlador principal siempre disponible
    if (options.mode === 'normal' || options.mode === 'server') {
      controllers.push(AuthController);
    }

    // Controlador OAuth si hay estrategias OAuth configuradas
    const hasOAuth =
      (options.strategies?.google && options.google) ||
      (options.strategies?.facebook && options.facebook) ||
      (options.strategies?.github && options.github);

    if (hasOAuth) {
      controllers.push(OAuthController);
    }

    return controllers;
  }

  /**
 * Crea el session store apropiado
 */
  private static createSessionStore(
    sessionConfig: SessionStoreConfig | undefined,
    configService?: ConfigService,
  ): ISessionStore {
    if (!sessionConfig || sessionConfig.type === 'memory') {
      return new MemorySessionStore();
    }

    if (sessionConfig.type === 'redis') {
      const redisConfig = sessionConfig.redis || {
        host: configService?.get('REDIS_HOST', 'localhost') || 'localhost',
        port: configService?.get('REDIS_PORT', 6379) || 6379,
        password: configService?.get('REDIS_PASSWORD'),
        db: configService?.get('REDIS_DB', 0) || 0,
        keyPrefix: configService?.get('REDIS_KEY_PREFIX', 'auth:') || 'auth:',
      };

      // Crear cliente Redis
      const redisClient = new Redis({
        host: redisConfig.host,
        port: redisConfig.port,
        password: redisConfig.password,
        db: redisConfig.db,
        keyPrefix: redisConfig.keyPrefix,
      });

      // Crear providers para inyección
      const providers = [
        {
          provide: 'REDIS_CLIENT',
          useValue: redisClient,
        },
        {
          provide: 'REDIS_CONFIG',
          useValue: { keyPrefix: redisConfig.keyPrefix },
        },
      ];

      // Retornar instancia manualmente (o mejor, usar el container de NestJS)
      return new RedisSessionStore(redisClient, { keyPrefix: redisConfig.keyPrefix });
    }

    return new MemorySessionStore();
  }

  /**
   * Crea el esquema de validación para variables de entorno
   */
  private static createValidationSchema() {
    return Joi.object({
      JWT_SECRET: Joi.string().required(),
      JWT_EXPIRES_IN: Joi.string().default('60m'),
      REFRESH_EXPIRES_IN: Joi.string().default('7d'),
      REDIS_HOST: Joi.string().when('SESSION_STORE_TYPE', {
        is: 'redis',
        then: Joi.required(),
        otherwise: Joi.optional(),
      }),
      REDIS_PORT: Joi.number().when('SESSION_STORE_TYPE', {
        is: 'redis',
        then: Joi.required(),
        otherwise: Joi.optional(),
      }),
      REDIS_PASSWORD: Joi.string().optional(),
      REDIS_DB: Joi.number().default(0),
      REDIS_KEY_PREFIX: Joi.string().default('auth:'),
      GOOGLE_CLIENT_ID: Joi.string().optional(),
      GOOGLE_CLIENT_SECRET: Joi.string().optional(),
      GOOGLE_CALLBACK_URL: Joi.string().optional(),
      FACEBOOK_APP_ID: Joi.string().optional(),
      FACEBOOK_APP_SECRET: Joi.string().optional(),
      FACEBOOK_CALLBACK_URL: Joi.string().optional(),
      GITHUB_CLIENT_ID: Joi.string().optional(),
      GITHUB_CLIENT_SECRET: Joi.string().optional(),
      GITHUB_CALLBACK_URL: Joi.string().optional(),
    });
  }
}