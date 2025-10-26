import { Injectable, Inject } from '@nestjs/common';
import { ISessionStore } from '../core/interfaces/session-store.interface';
import { Redis } from 'ioredis';

@Injectable()
export class RedisSessionStore implements ISessionStore {
  constructor(
    @Inject('REDIS_CLIENT') private readonly redis: Redis,
  ) { }

  async set(key: string, value: any, ttl?: number): Promise<void> {
    const serialized = JSON.stringify(value);
    if (ttl) {
      await this.redis.setex(key, ttl, serialized);
    } else {
      await this.redis.set(key, serialized);
    }
  }

  async get(key: string): Promise<any> {
    const data = await this.redis.get(key);
    return data ? JSON.parse(data) : null;
  }

  async delete(key: string): Promise<void> {
    await this.redis.del(key);
  }

  async exists(key: string): Promise<boolean> {
    const result = await this.redis.exists(key);
    return result === 1;
  }
}