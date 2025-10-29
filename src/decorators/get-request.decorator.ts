import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Extrae el objeto request completo
 */
export const GetRequest = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    return ctx.switchToHttp().getRequest();
  },
);