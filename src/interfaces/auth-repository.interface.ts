import { AuthUser } from "./auth-options.interface";

/**
 * Interface que debe implementar el repositorio de autenticación
 * Permite abstraer la capa de datos (TypeORM, Prisma, Mongoose, etc.)
 */
export interface IAuthRepository {
  /**
   * Busca un usuario por nombre de usuario
   * IMPORTANTE: Debe retornar el password en el nivel superior del objeto
   * para que validateUser() funcione correctamente
   * 
   * @returns AuthUser con password incluido, o null si no existe
   */
  findUserByUsername(username: string): Promise<AuthUser | null>;
  /**
   * Busca un usuario por email
   * IMPORTANTE: Debe retornar el password en el nivel superior del objeto
   * para que validateUser() funcione correctamente
   * 
   * @returns AuthUser con password incluido, o null si no existe
   */
  findUserByEmail(email: string): Promise<AuthUser | null>;

  /**
   * Busca un usuario por ID
   * IMPORTANTE: Debe retornar el password en el nivel superior del objeto
   * 
   * @returns AuthUser con password incluido, o null si no existe
   */
  findUserById(id: string): Promise<AuthUser | null>;

  /**
   * Busca un usuario por proveedor OAuth y ID del proveedor
   * Para OAuth no se requiere password
   */
  findUserByProviderId(
    provider: string,
    providerId: string
  ): Promise<Omit<AuthUser, 'password'> | null>;

  /**
   * Crea un nuevo usuario
   * @param data - Datos del usuario. Si incluye password, debe estar hasheado
   */
  createUser(data: Partial<AuthUser>): Promise<AuthUser>;

  /**
   * Actualiza un usuario existente
   * @param id - ID del usuario
   * @param data - Datos a actualizar (sin password o con password hasheado)
   */
  updateUser(id: string, data: Partial<AuthUser>): Promise<AuthUser>;

  /**
   * Elimina un usuario (soft delete recomendado)
   */
  deleteUser?(id: string): Promise<void>;

  /**
   * Busca usuarios por rol
   */
  findUsersByRole?(role: string): Promise<AuthUser[]>;

  /**
   * Busca usuarios activos
   */
  findActiveUsers?(): Promise<AuthUser[]>;
}