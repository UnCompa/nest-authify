/**
 * Interface para almacenamiento de sesiones
 */
export interface ISessionStore {
  /**
   * Almacena un valor
   */
  set(key: string, value: any, ttl?: number): Promise<void>;

  /**
   * Obtiene un valor
   */
  get(key: string): Promise<any>;

  /**
   * Elimina un valor
   */
  delete(key: string): Promise<void>;

  /**
   * Verifica si existe una clave
   */
  exists(key: string): Promise<boolean>;

  /**
   * Obtiene todas las claves que coincidan con un patrón
   */
  keys(pattern?: string): Promise<string[]>;

  /**
   * Limpia todas las claves
   */
  clear(): Promise<void>;
}

