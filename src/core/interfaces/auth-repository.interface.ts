export interface IAuthRepository {
  findUserByUsername(username: string): Promise<any>;
  findUserById(id: string): Promise<any>;
  findUserByProviderId(provider: string, providerId: string): Promise<any>;
  createUser(data: any): Promise<any>;
  updateUser(id: string, data: any): Promise<any>;
}