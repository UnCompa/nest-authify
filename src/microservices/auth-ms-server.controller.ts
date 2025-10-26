import { Controller, Inject, UnauthorizedException } from '@nestjs/common';
import { MessagePattern } from '@nestjs/microservices';
import { IAuthService } from '../core/interfaces/auth-service.interface';

@Controller()
export class AuthMsServerController {
  constructor(
    @Inject('AUTH_SERVICE') private authService: IAuthService,
  ) { }

  @MessagePattern({ cmd: 'validate_token' })
  async validateToken(data: { token: string }) {
    try {
      return await this.authService.verifyToken(data.token);
    } catch (error) {
      return { error: 'Invalid token' };
    }
  }

  @MessagePattern({ cmd: 'get_user' })
  async getUser(data: { userId: string }) {
    return this.authService.getUserById(data.userId);
  }

  @MessagePattern({ cmd: 'login' })
  async login(data: { username: string; password: string }) {
    if (!this.authService || typeof this.authService.createSession !== 'function') {
            throw new UnauthorizedException('Authentication service unavailable');
          }
    try {
      const user = await this.authService.validateUser(data.username, data.password);
      if (!user) {
        return { error: 'Invalid credentials' };
      }
      return await this.authService.createSession(user);
    } catch (error) {
      return { error: 'Authentication failed' };
    }
  }

  @MessagePattern({ cmd: 'refresh_token' })
  async refreshToken(data: { refreshToken: string }) {
    try {
      return await this.authService.refreshAccessToken(data.refreshToken);
    } catch (error) {
      return { error: 'Invalid refresh token' };
    }
  }
}
