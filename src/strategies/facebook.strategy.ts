import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile } from 'passport-facebook';
import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { IAuthService } from '../core/interfaces/auth-service.interface';
import { ProvidersAuth } from '../core/types/auth-session.interface';

@Injectable()
export class FacebookStrategy extends PassportStrategy(Strategy, 'facebook') {
  constructor(
    @Inject('AUTH_CONFIG') private config: any,
    @Inject('AUTH_SERVICE') private authService: IAuthService,
  ) {
    super({
      clientID: config.facebook?.clientId,
      clientSecret: config.facebook?.clientSecret,
      callbackURL: config.facebook?.callbackUrl || 'http://localhost:3000/auth/facebook/callback',
      scope: ['email'],
      profileFields: ['emails', 'name', 'photos'],
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
      const user = await this.authService.validateOAuthUser(profile, ProvidersAuth.FACEBOOK);
      done(null, user);
    } catch (error) {
      done(error, false);
    }
  }
}