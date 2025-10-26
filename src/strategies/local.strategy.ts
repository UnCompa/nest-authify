import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { IAuthService } from '../core/interfaces/auth-service.interface';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(
    @Inject('AUTH_SERVICE') private authService: IAuthService,
  ) {
    super({ usernameField: 'username' });
  }

  async validate(username: string, password: string): Promise<any> {
    if (!this.authService || typeof this.authService.validateUser !== 'function') {
      throw new UnauthorizedException('Authentication service unavailable');
    }

    const user = await this.authService.validateUser(username, password);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    return user;
  }
}