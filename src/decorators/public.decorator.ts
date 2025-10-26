import { Auth } from './auth.decorator';

/**
 * Marca una ruta como pública (sin autenticación requerida)
 */
export const Public = () => Auth({ public: true });