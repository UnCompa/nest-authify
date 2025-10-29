/**
 * Tokens de inyección de dependencias
 */

/**
 * Token para inyectar las opciones del módulo
 */
export const AUTH_MODULE_OPTIONS = 'AUTH_MODULE_OPTIONS';

/**
 * Token para inyectar el servicio de autenticación
 */
export const AUTH_SERVICE = 'AUTH_SERVICE';

/**
 * Token para inyectar el session store
 */
export const SESSION_STORE = 'SESSION_STORE';

/**
 * Token para inyectar el repositorio de autenticación
 */
export const AUTH_REPOSITORY = 'AUTH_REPOSITORY';

/**
 * Token para inyectar el servicio de hash
 */
export const HASH_SERVICE = 'HASH_SERVICE';

/**
 * Prefijos para almacenamiento de sesiones
 */
export const SESSION_PREFIX = 'session:';
export const REFRESH_TOKEN_PREFIX = 'refresh:';
export const RESET_PASSWORD_PREFIX = 'reset:';

/**
 * Duraciones por defecto
 */
export const DEFAULT_JWT_EXPIRES_IN = '60m';
export const DEFAULT_REFRESH_EXPIRES_IN = '7d';
export const DEFAULT_RESET_PASSWORD_EXPIRES_IN = '1h';

/**
 * Roles por defecto
 */
export const DEFAULT_ROLES = {
  USER: 'user',
  ADMIN: 'admin',
  MODERATOR: 'moderator',
} as const;

/**
 * Permisos por defecto
 */
export const DEFAULT_PERMISSIONS = {
  READ: 'read',
  WRITE: 'write',
  DELETE: 'delete',
  UPDATE: 'update',
} as const;