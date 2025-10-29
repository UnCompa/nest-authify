import { Injectable } from '@nestjs/common';
import { ISessionStore } from '../interfaces/session-store.interface';

@Injectable()
export class MemorySessionStore implements ISessionStore {
  private store = new Map<string, { value: any; expiry?: number }>();

  async keys(pattern?: string): Promise<string[]> {
    const allKeys = Array.from(this.store.keys());

    if (!pattern) {
      return allKeys;
    }

    // Convertir patrón de Redis (wildcards) a RegExp
    const regexPattern = pattern
      .replace(/\*/g, '.*')  // * -> .*
      .replace(/\?/g, '.');   // ? -> .

    const regex = new RegExp(`^${regexPattern}$`);

    return allKeys.filter(key => regex.test(key));
  }

  async clear(): Promise<void> {
    this.store.clear();
  }

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

  /**
   * Limpieza automática de keys expiradas
   * Útil para evitar memory leaks en el store en memoria
   */
  private cleanupExpired(): void {
    const now = Date.now();
    for (const [key, item] of this.store.entries()) {
      if (item.expiry && now > item.expiry) {
        this.store.delete(key);
      }
    }
  }

  /**
   * Iniciar limpieza periódica (llamar en el constructor o al inicializar)
   */
  startPeriodicCleanup(intervalMs: number = 60000): NodeJS.Timeout {
    return setInterval(() => this.cleanupExpired(), intervalMs);
  }
}