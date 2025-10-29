import { applyDecorators, UseGuards, Type } from '@nestjs/common';
import { ApiBearerAuth, ApiUnauthorizedResponse } from '@nestjs/swagger';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { RolesGuard } from '../guards/roles.guard';
import { PermissionsGuard } from '../guards/permissions.guard';
import { Public } from './public.decorator';
import { Roles } from './roles.decorator';
import { Permissions } from './permissions.decorator';

export interface AuthOptions {
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
  guards?: Type<any>[];

  /**
   * Habilitar documentación Swagger
   * @default true
   */
  swagger?: boolean;
}

/**
 * Decorador unificado para autenticación y autorización
 * Combina guards, roles, permisos y documentación Swagger
 * 
 * @example
 * // Ruta pública
 * @Auth({ public: true })
 * 
 * @example
 * // Requiere autenticación
 * @Auth()
 * 
 * @example
 * // Requiere roles específicos
 * @Auth({ roles: ['admin', 'moderator'] })
 * 
 * @example
 * // Requiere permisos específicos
 * @Auth({ permissions: ['posts:write', 'posts:delete'] })
 * 
 * @example
 * // Combinación de roles, permisos y guards personalizados
 * @Auth({ 
 *   roles: ['admin'], 
 *   permissions: ['users:delete'],
 *   guards: [ThrottlerGuard]
 * })
 */
export function Auth(options: AuthOptions = {}): MethodDecorator {
  const decorators: (ClassDecorator | MethodDecorator | PropertyDecorator)[] = [];

  // Si es público, solo marcar como público
  if (options.public) {
    decorators.push(Public());
    return applyDecorators(...decorators);
  }

  // Añadir guards básicos
  const guards: Type<any>[] = [JwtAuthGuard, RolesGuard, PermissionsGuard];

  // Añadir guards personalizados
  if (options.guards && options.guards.length > 0) {
    guards.push(...options.guards);
  }

  decorators.push(UseGuards(...guards));

  // Añadir roles si están definidos
  if (options.roles && options.roles.length > 0) {
    decorators.push(Roles(...options.roles));
  }

  // Añadir permisos si están definidos
  if (options.permissions && options.permissions.length > 0) {
    decorators.push(Permissions(...options.permissions));
  }

  // Añadir documentación Swagger por defecto
  if (options.swagger !== false) {
    decorators.push(
      ApiBearerAuth(),
      ApiUnauthorizedResponse({ description: 'Unauthorized' }),
    );
  }

  return applyDecorators(...decorators);
}
