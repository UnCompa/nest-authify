import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { IAuthService } from '../core/interfaces/auth-service.interface';
import { ProvidersAuth } from '../core/types/auth-session.interface';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    @Inject('AUTH_CONFIG') private config: any,
    @Inject('AUTH_SERVICE') private authService: IAuthService,
  ) {
    super({
      clientID: config.google?.clientId,
      clientSecret: config.google?.clientSecret,
      callbackURL: config.google?.callbackUrl || 'http://localhost:3000/auth/google/callback',
      scope: ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    try {
      if (!this.authService || typeof this.authService.validateOAuthUser !== 'function') {
            throw new UnauthorizedException('Authentication service unavailable');
          }
      const user = await this.authService.validateOAuthUser(profile, ProvidersAuth.GOOGLE);
      done(null, user);
    } catch (error) {
      done(error, false);
    }
  }
}
