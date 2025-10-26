import { Injectable } from '@nestjs/common';
import { ISessionStore } from '../core/interfaces/session-store.interface';

@Injectable()
export class MemorySessionStore implements ISessionStore {
  private store = new Map<string, { value: any; expiry?: number }>();

  async set(key: string, value: any, ttl?: number): Promise<void> {
    const expiry = ttl ? Date.now() + ttl * 1000 : undefined;
    this.store.set(key, { value, expiry });
  }

  async get(key: string): Promise<any> {
    const item = this.store.get(key);
    if (!item) return null;

    if (item.expiry && Date.now() > item.expiry) {
      this.store.delete(key);
      return null;
    }

    return item.value;
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async exists(key: string): Promise<boolean> {
    const item = this.store.get(key);
    if (!item) return false;

    if (item.expiry && Date.now() > item.expiry) {
      this.store.delete(key);
      return false;
    }

    return true;
  }
}