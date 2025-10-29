import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Extrae el usuario del request
 * @param data Propiedad específica del usuario a extraer (opcional)
 */
export const CurrentUser = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;

    return data ? user?.[data] : user;
  },
);

