import { SetMetadata, UseGuards, applyDecorators } from '@nestjs/common';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';

export const IS_PUBLIC_KEY = 'isPublic';
export const ROLES_KEY = 'roles';

export function Auth(options: { isPublic?: boolean; roles?: string[] } = {}) {
  const { isPublic = false, roles = [] } = options;
  return applyDecorators(
    SetMetadata(IS_PUBLIC_KEY, isPublic),
    SetMetadata(ROLES_KEY, roles),
    UseGuards(JwtAuthGuard),
  );
}