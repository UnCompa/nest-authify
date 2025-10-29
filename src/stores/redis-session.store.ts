import { Injectable } from '@nestjs/common';
import Redis from 'ioredis';
import { RedisConfig } from '../interfaces/auth-options.interface';
import { ISessionStore } from '../interfaces/session-store.interface';

/**
 * Implementación con Redis del session store
 * Requiere que Redis esté instalado: npm install ioredis
 */
@Injectable()
export class RedisSessionStore implements ISessionStore {
  private client: Redis;

  constructor(config: RedisConfig) {
    this.client = new Redis({
      host: config.host,
      port: config.port,
      password: config.password,
      db: config.db || 0,
      keyPrefix: config.keyPrefix || 'auth:',
      retryStrategy: (times) => {
        const delay = Math.min(times * 50, 2000);
        return delay;
      },
    });

    this.client.on('error', (err) => {
      console.error('Redis Client Error:', err);
    });

    this.client.on('connect', () => {
      console.log('Redis Client Connected');
    });
  }

  async set(key: string, value: any, ttl?: number): Promise<void> {
    const serialized = JSON.stringify(value);
    if (ttl) {
      await this.client.setex(key, ttl, serialized);
    } else {
      await this.client.set(key, serialized);
    }
  }

  async get(key: string): Promise<any> {
    const value = await this.client.get(key);
    if (!value) return null;

    try {
      return JSON.parse(value);
    } catch (error) {
      return value;
    }
  }

  async delete(key: string): Promise<void> {
    await this.client.del(key);
  }

  async exists(key: string): Promise<boolean> {
    const result = await this.client.exists(key);
    return result === 1;
  }

  async keys(pattern: string = '*'): Promise<string[]> {
    // Usar SCAN en lugar de KEYS para mejor rendimiento
    const keys: string[] = [];
    let cursor = '0';

    do {
      const [newCursor, foundKeys] = await this.client.scan(
        cursor,
        'MATCH',
        pattern,
        'COUNT',
        100,
      );
      cursor = newCursor;
      keys.push(...foundKeys);
    } while (cursor !== '0');

    return keys;
  }

  async clear(): Promise<void> {
    await this.client.flushdb();
  }

  /**
   * Cierra la conexión al destruir
   */
  async onModuleDestroy(): Promise<void> {
    await this.client.quit();
  }

  /**
   * Obtiene el cliente Redis para operaciones avanzadas
   */
  getClient(): Redis {
    return this.client;
  }
}