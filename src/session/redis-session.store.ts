import { Inject, Injectable } from '@nestjs/common';
import { Redis } from 'ioredis';
import { ISessionStore } from '../interfaces/session-store.interface';

@Injectable()
export class RedisSessionStore implements ISessionStore {
  private readonly keyPrefix: string;

  constructor(
    @Inject('REDIS_CLIENT') private readonly redis: Redis,
    @Inject('REDIS_CONFIG') private readonly config?: { keyPrefix?: string },
  ) {
    // Obtener el keyPrefix de la configuración o usar el default
    this.keyPrefix = config?.keyPrefix || this.redis.options.keyPrefix || '';
  }

  /**
   * Obtiene todas las keys que coincidan con el patrón
   * Por defecto busca todas las keys con el keyPrefix del store
   * @param pattern - Patrón de búsqueda (opcional). Si no se provee, busca todas las keys del prefix
   * @example
   * keys() // Retorna todas las keys con el keyPrefix: ['auth:session:1', 'auth:session:2']
   * keys('session:*') // Retorna solo las keys que coincidan: ['auth:session:1', 'auth:session:2']
   * keys('user:*') // Retorna: ['auth:user:123']
   */
  async keys(pattern?: string): Promise<string[]> {
    // Construir el patrón de búsqueda
    const searchPattern = pattern
      ? `${this.keyPrefix}${pattern}`
      : `${this.keyPrefix}*`;

    // Usar SCAN en lugar de KEYS para mejor performance en producción
    const keys: string[] = [];
    let cursor = '0';

    do {
      const [nextCursor, foundKeys] = await this.redis.scan(
        cursor,
        'MATCH',
        searchPattern,
        'COUNT',
        100, // Procesar 100 keys por iteración
      );

      cursor = nextCursor;

      // Remover el keyPrefix de las keys retornadas para mantener consistencia
      const cleanKeys = foundKeys.map(key =>
        this.keyPrefix ? key.replace(this.keyPrefix, '') : key
      );

      keys.push(...cleanKeys);
    } while (cursor !== '0');

    return keys;
  }

  /**
   * Limpia todas las keys que pertenecen a este store (usando el keyPrefix)
   * IMPORTANTE: Solo borra las keys con el keyPrefix configurado, no toda la DB
   * @example
   * // Si keyPrefix es 'auth:', solo borra keys que empiecen con 'auth:'
   * await store.clear(); // Borra 'auth:session:1', 'auth:user:123', etc.
   *                      // NO borra 'other:key:1' o keys sin el prefix
   */
  async clear(): Promise<void> {
    if (!this.keyPrefix) {
      throw new Error(
        'Cannot clear Redis without a keyPrefix. This would delete ALL keys in the database. ' +
        'Please configure a keyPrefix in your Redis configuration.'
      );
    }

    // Buscar todas las keys con el keyPrefix
    const pattern = `${this.keyPrefix}*`;
    let cursor = '0';
    const pipeline = this.redis.pipeline();
    let keysToDelete = 0;

    do {
      const [nextCursor, keys] = await this.redis.scan(
        cursor,
        'MATCH',
        pattern,
        'COUNT',
        100,
      );

      cursor = nextCursor;

      if (keys.length > 0) {
        // Agregar las keys al pipeline para borrado en lote
        keys.forEach(key => pipeline.del(key));
        keysToDelete += keys.length;
      }
    } while (cursor !== '0');

    // Ejecutar el pipeline si hay keys para borrar
    if (keysToDelete > 0) {
      await pipeline.exec();
    }
  }

  async set(key: string, value: any, ttl?: number): Promise<void> {
    const serialized = JSON.stringify(value);
    const fullKey = `${this.keyPrefix}${key}`;

    if (ttl) {
      await this.redis.setex(fullKey, ttl, serialized);
    } else {
      await this.redis.set(fullKey, serialized);
    }
  }

  async get(key: string): Promise<any> {
    const fullKey = `${this.keyPrefix}${key}`;
    const data = await this.redis.get(fullKey);
    return data ? JSON.parse(data) : null;
  }

  async delete(key: string): Promise<void> {
    const fullKey = `${this.keyPrefix}${key}`;
    await this.redis.del(fullKey);
  }

  async exists(key: string): Promise<boolean> {
    const fullKey = `${this.keyPrefix}${key}`;
    const result = await this.redis.exists(fullKey);
    return result === 1;
  }

  /**
   * Método adicional útil: Obtener TTL de una key
   */
  async getTTL(key: string): Promise<number> {
    const fullKey = `${this.keyPrefix}${key}`;
    return this.redis.ttl(fullKey);
  }

  /**
   * Método adicional útil: Renovar TTL de una key existente
   */
  async refreshTTL(key: string, ttl: number): Promise<boolean> {
    const fullKey = `${this.keyPrefix}${key}`;
    const result = await this.redis.expire(fullKey, ttl);
    return result === 1;
  }

  /**
   * Método adicional útil: Obtener todas las keys con sus valores
   */
  async getAllWithValues(pattern?: string): Promise<Record<string, any>> {
    const keys = await this.keys(pattern);
    const result: Record<string, any> = {};

    if (keys.length === 0) {
      return result;
    }

    // Usar pipeline para mejor performance
    const pipeline = this.redis.pipeline();
    keys.forEach(key => {
      const fullKey = `${this.keyPrefix}${key}`;
      pipeline.get(fullKey);
    });

    const values = await pipeline.exec();

    keys.forEach((key, index) => {
      const [err, value] = values![index];
      if (!err && value) {
        try {
          result[key] = JSON.parse(value as string);
        } catch {
          result[key] = value;
        }
      }
    });

    return result;
  }
}