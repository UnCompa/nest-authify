import { SetMetadata } from '@nestjs/common';

export const ROLES_KEY = 'roles';

/**
 * Define los roles requeridos para acceder a una ruta
 * @param roles Array de roles permitidos
 */
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);
