export interface ISessionStore {
  set(key: string, value: any, ttl?: number): Promise<void>;
  get(key: string): Promise<any>;
  delete(key: string): Promise<void>;
  exists(key: string): Promise<boolean>;
}