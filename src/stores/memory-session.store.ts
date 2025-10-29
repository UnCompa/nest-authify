import { Injectable } from '@nestjs/common';
import { ISessionStore } from '../interfaces/session-store.interface';

/**
 * Implementación en memoria del session store
 * Útil para desarrollo o cuando no se necesita persistencia
 */
@Injectable()
export class MemorySessionStore implements ISessionStore {
  private store: Map<string, { value: any; expiresAt?: number }> = new Map();
  private cleanupInterval: NodeJS.Timeout;

  constructor() {
    // Limpieza automática cada 5 minutos
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 5 * 60 * 1000);
  }

  async set(key: string, value: any, ttl?: number): Promise<void> {
    const expiresAt = ttl ? Date.now() + ttl * 1000 : undefined;
    this.store.set(key, { value, expiresAt });
  }

  async get(key: string): Promise<any> {
    const item = this.store.get(key);
    if (!item) return null;

    // Verificar si ha expirado
    if (item.expiresAt && item.expiresAt < Date.now()) {
      this.store.delete(key);
      return null;
    }

    return item.value;
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async exists(key: string): Promise<boolean> {
    const value = await this.get(key);
    return value !== null;
  }

  async keys(pattern?: string): Promise<string[]> {
    const allKeys = Array.from(this.store.keys());
    if (!pattern) return allKeys;

    // Convertir patrón glob simple a regex
    const regex = new RegExp(
      '^' + pattern.replace(/\*/g, '.*').replace(/\?/g, '.') + '$',
    );
    return allKeys.filter((key) => regex.test(key));
  }

  async clear(): Promise<void> {
    this.store.clear();
  }

  /**
   * Limpia entradas expiradas
   */
  private cleanup(): void {
    const now = Date.now();
    for (const [key, item] of this.store.entries()) {
      if (item.expiresAt && item.expiresAt < now) {
        this.store.delete(key);
      }
    }
  }

  /**
   * Limpia el intervalo al destruir
   */
  onModuleDestroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
  }
}
