import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Extrae el User-Agent del request
 */
export const UserAgent = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.headers['user-agent'];
  },
);
