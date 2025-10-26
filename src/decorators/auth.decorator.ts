import { SetMetadata, UseGuards, applyDecorators } from '@nestjs/common';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { RolesGuard } from '../guards/roles.guard';

export const IS_PUBLIC_KEY = 'isPublic';
export const ROLES_KEY = 'roles';
export const PERMISSIONS_KEY = 'permissions';

export interface AuthDecoratorOptions {
  /**
   * Si es true, la ruta es pública y no requiere autenticación
   */
  public?: boolean;

  /**
   * Roles requeridos para acceder a la ruta
   */
  roles?: string[];

  /**
   * Permisos requeridos para acceder a la ruta
   */
  permissions?: string[];

  /**
   * Guards adicionales a aplicar
   */
  guards?: any[];
}

/**
 * Decorador unificado para autenticación y autorización
 * 
 * @example
 * // Ruta pública
 * @Auth({ public: true })
 * 
 * @example
 * // Solo usuarios autenticados
 * @Auth()
 * 
 * @example
 * // Solo admins
 * @Auth({ roles: ['admin'] })
 * 
 * @example
 * // Admins o moderadores con permisos específicos
 * @Auth({ 
 *   roles: ['admin', 'moderator'],
 *   permissions: ['posts:write']
 * })
 */
export function Auth(options: AuthDecoratorOptions = {}) {
  const {
    public: isPublic = false,
    roles = [],
    permissions = [],
    guards = [],
  } = options;

  const metadataDecorators = [
    SetMetadata(IS_PUBLIC_KEY, isPublic),
    SetMetadata(ROLES_KEY, roles),
    SetMetadata(PERMISSIONS_KEY, permissions),
  ];

  // Si es público, solo metadata
  if (isPublic) {
    return applyDecorators(...metadataDecorators);
  }

  // Si no es público: metadata + guards
  const guardDecorators = guards.length > 0
    ? UseGuards(JwtAuthGuard, RolesGuard, ...guards)
    : UseGuards(JwtAuthGuard, RolesGuard);

  return applyDecorators(...metadataDecorators, guardDecorators);
}