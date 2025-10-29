// src/strategies/google.strategy.ts

import { Injectable } from '@nestjs/common';
import { BaseAuthService } from '../services/base-auth.service';
import { GoogleOAuthConfig } from '../interfaces/auth-options.interface';

@Injectable()
export class GoogleStrategy {
  private strategy: any = null;

  constructor(
    private readonly authService: BaseAuthService,
    private readonly config: GoogleOAuthConfig,
  ) {
    this.init();
  }

  private async init() {
    try {
      const { Strategy } = await import('passport-google-oauth20');

      this.strategy = new Strategy(
        {
          clientID: this.config.clientId,
          clientSecret: this.config.clientSecret,
          callbackURL: this.config.callbackUrl || 'http://localhost:3000/auth/google/callback',
          scope: this.config.scope || ['email', 'profile'],
        },
        async (accessToken: string, refreshToken: string, profile: any, done: any) => {
          try {
            const { id, name, emails, photos } = profile;
            const user = await this.authService.validateOAuthUser('google', id, {
              email: emails?.[0]?.value,
              username: emails?.[0]?.value || `google_${id}`,
              displayName: `${name?.givenName} ${name?.familyName}`.trim(),
              photo: photos?.[0]?.value,
            });
            done(null, user);
          } catch (err) {
            done(err);
          }
        },
      );

      const passport = (await import('passport')).default || (await import('passport'));
      passport.use('google', this.strategy);
    } catch (err: any) {
      if (err.code === 'MODULE_NOT_FOUND') {
        console.warn('passport-google-oauth20 no instalado. Google OAuth desactivado.');
      } else {
        console.error('Error cargando Google Strategy:', err);
      }
      this.strategy = null;
    }
  }

  getStrategy() {
    return this.strategy;
  }

  isEnabled(): boolean {
    return this.strategy !== null;
  }
}