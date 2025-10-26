import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile } from 'passport-github2';
import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { IAuthService } from '../core/interfaces/auth-service.interface';
import { ProvidersAuth } from '../core/types/auth-session.interface';

@Injectable()
export class GithubStrategy extends PassportStrategy(Strategy, 'github') {
  constructor(
    @Inject('AUTH_CONFIG') private config: any,
    @Inject('AUTH_SERVICE') private authService: IAuthService,
  ) {
    super({
      clientID: config.github?.clientId,
      clientSecret: config.github?.clientSecret,
      callbackURL: config.github?.callbackUrl || 'http://localhost:3000/auth/github/callback',
      scope: ['user:email'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: (err: any, user: any, info?: any) => void,
  ): Promise<any> {
    try {
      if (!this.authService || typeof this.authService.validateOAuthUser !== 'function') {
        throw new UnauthorizedException('Authentication service unavailable');
      }
      const user = await this.authService.validateOAuthUser(profile, ProvidersAuth.GITHUB);
      done(null, user);
    } catch (error) {
      done(error, false);
    }
  }
}