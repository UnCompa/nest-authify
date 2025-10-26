import { Auth } from './auth.decorator';

/**
 * Requiere que el usuario tenga alguno de los roles especificados
 */
export const Roles = (...roles: string[]) => Auth({ roles });