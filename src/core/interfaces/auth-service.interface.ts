export interface IAuthService {
  validateUser(username: string, password: string): Promise<any>;
  validateOAuthUser?(profile: any, provider: string): Promise<any>;
  getUserById(userId: string): Promise<any>;
  verifyToken(token: string): Promise<any>;
  refreshAccessToken(refreshToken: string): Promise<any>;
  validateOAuthUser?(profile: any, provider: string): Promise<any>;
  getUserById(userId: string): Promise<any>;
  createSession?(user: any, options?: any): Promise<any>;
}
