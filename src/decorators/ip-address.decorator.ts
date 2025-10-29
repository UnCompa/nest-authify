import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Extrae la dirección IP del cliente
 */
export const IpAddress = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.ip || request.connection.remoteAddress;
  },
);
