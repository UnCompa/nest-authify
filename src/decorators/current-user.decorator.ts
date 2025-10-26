import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Inyecta el usuario actual en el parámetro del controlador
 */
export const CurrentUser = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;

    return data ? user?.[data] : user;
  },
);