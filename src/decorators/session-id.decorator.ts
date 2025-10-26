import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Inyecta el sessionId del token JWT
 */
export const SessionId = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user?.sessionId;
  },
);