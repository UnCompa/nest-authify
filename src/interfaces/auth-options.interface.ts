import { ModuleMetadata, Type } from '@nestjs/common';

/**
 * Modo de operación del módulo de autenticación
 */
export type AuthMode = 'normal' | 'server' | 'client';

/**
 * Configuración de Redis para sesiones
 */
export interface RedisConfig {
  host: string;
  port: number;
  password?: string;
  db?: number;
  keyPrefix?: string;
  ttl?: number;
}

/**
 * Configuración del almacén de sesiones
 */
export interface SessionStoreConfig {
  type: 'memory' | 'redis';
  redis?: RedisConfig;
}

/**
 * Configuración de Google OAuth
 */
export interface GoogleOAuthConfig {
  clientId: string;
  clientSecret: string;
  callbackUrl?: string;
  scope?: string[];
}

/**
 * Configuración de Facebook OAuth
 */
export interface FacebookOAuthConfig {
  clientId: string;
  clientSecret: string;
  callbackUrl?: string;
  scope?: string[];
  profileFields?: string[];
}

/**
 * Configuración de GitHub OAuth
 */
export interface GithubOAuthConfig {
  clientId: string;
  clientSecret: string;
  callbackUrl?: string;
  scope?: string[];
}

/**
 * Estrategias de autenticación a habilitar
 */
export interface AuthStrategies {
  local?: boolean;
  jwt?: boolean;
  google?: boolean;
  facebook?: boolean;
  github?: boolean;
}

/**
 * Callback para hash personalizado
 */
export type HashCallback = (password: string) => Promise<string>;

/**
 * Callback para verificación de hash personalizado
 */
export type HashVerifyCallback = (
  password: string,
  hash: string,
) => Promise<boolean>;

/**
 * Opciones de configuración del módulo Auth
 */
export interface AuthModuleOptions {
  /**
   * Modo de operación
   * - 'normal': Aplicación monolítica completa
   * - 'server': Microservicio servidor de autenticación
   * - 'client': Microservicio cliente que consume autenticación
   */
  mode: AuthMode;

  /**
   * Secret para firmar JWT
   */
  jwtSecret: string;

  /**
   * Tiempo de expiración del access token
   * @default '60m'
   */
  jwtExpiresIn?: string;

  /**
   * Tiempo de expiración del refresh token
   * @default '7d'
   */
  refreshExpiresIn?: string;

  /**
   * Configuración del almacén de sesiones
   * Si no se proporciona, se usa memoria por defecto
   */
  sessionStore?: SessionStoreConfig;

  /**
   * Clase del servicio de autenticación personalizado
   * Debe extender BaseAuthService
   */
  authService?: Type<any>;

  /**
   * Clase del repositorio de autenticación
   * Debe implementar IAuthRepository
   */
  authRepository?: Type<any>;

  /**
   * Callback para hash de contraseñas personalizado
   * Si no se proporciona, se usa bcrypt por defecto
   */
  hashCallback?: HashCallback;

  /**
   * Callback para verificación de hash personalizado
   * Si no se proporciona, se usa bcrypt por defecto
   */
  hashVerifyCallback?: HashVerifyCallback;

  /**
   * Configuración de Google OAuth
   */
  google?: GoogleOAuthConfig;

  /**
   * Configuración de Facebook OAuth
   */
  facebook?: FacebookOAuthConfig;

  /**
   * Configuración de GitHub OAuth
   */
  github?: GithubOAuthConfig;

  /**
   * Estrategias de autenticación a habilitar
   */
  strategies?: AuthStrategies;

  /**
   * Opciones para microservicios
   */
  microserviceOptions?: {
    transport?: any;
    options?: any;
  };

  /**
   * Habilitar controladores automáticos
   * @default true
   */
  enableControllers?: boolean;

  /**
   * Prefijo de rutas para los controladores
   * @default 'auth'
   */
  controllersPrefix?: string;

  /**
   * Habilitar Swagger en controladores
   * @default true
   */
  enableSwagger?: boolean;
}

/**
 * Opciones para configuración asíncrona
 */
export interface AuthModuleAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
  useFactory: (...args: any[]) => Promise<AuthModuleOptions> | AuthModuleOptions;
  inject?: any[];
}

/**
 * Payload del JWT
 */
export interface JwtPayload {
  sub: string; // user ID
  username?: string;
  email?: string;
  roles?: string[];
  permissions?: string[];
  sessionId?: string;
  iat?: number;
  exp?: number;
}

/**
 * Sesión de autenticación
 */
export interface AuthSession {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: string;
  sub: string;
  sessionId: string;
  [key: string]: any; // Campos adicionales extendibles
}

/**
 * Usuario para autenticación
 */
export interface AuthUser {
  id: string;
  username?: string;
  email?: string;
  password?: string; // DEBE estar en el nivel superior para validación
  roles?: string[];
  permissions?: string[];
  isActive?: boolean;
  emailVerified?: boolean;
  provider?: string;
  providerId?: string;
  [key: string]: any; // Permitir campos adicionales
}

/**
 * Resultado de validación de usuario
 */
export interface ValidatedUser {
  id: string;
  username?: string;
  email?: string;
  roles?: string[];
  permissions?: string[];
  [key: string]: any;
}

/**
 * Datos para registro de usuario
 */
export interface RegisterUserDto {
  username?: string;
  email: string;
  password: string;
  [key: string]: any;
}

/**
 * Datos para login
 */
export interface LoginDto {
  username?: string;
  email?: string;
  password: string;
}

/**
 * Respuesta de login
 */
export interface LoginResponse extends AuthSession {
  user: Partial<AuthUser>;
}

/**
 * Opciones para crear sesión
 */
export interface CreateSessionOptions {
  provider?: string;
  providerId?: string;
  expiresIn?: string;
  refreshExpiresIn?: string;
  metadata?: Record<string, any>;
}