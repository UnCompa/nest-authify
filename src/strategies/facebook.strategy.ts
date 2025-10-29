// src/strategies/facebook.strategy.ts

import { Injectable } from '@nestjs/common';
import { Profile } from 'passport-facebook';
import { FacebookOAuthConfig } from '../interfaces/auth-options.interface';
import { BaseAuthService } from '../services/base-auth.service';

@Injectable()
export class FacebookStrategy {
  private strategy: any;

  constructor(
    private readonly authService: BaseAuthService,
    private readonly config: FacebookOAuthConfig,
  ) {
    this.init();
  }

  private async init() {
    try {
      const { Strategy } = await import('passport-facebook');

      this.strategy = new Strategy(
        {
          clientID: this.config.clientId,
          clientSecret: this.config.clientSecret,
          callbackURL: this.config.callbackUrl || 'http://localhost:3000/auth/facebook/callback',
          scope: this.config.scope || ['email'],
          profileFields: this.config.profileFields || ['id', 'emails', 'name', 'photos'],
        },
        async (accessToken: string, refreshToken: string, profile: Profile, done: any) => {
          try {
            const { id, name, emails, photos } = profile;
            const user = await this.authService.validateOAuthUser('facebook', id, {
              email: emails?.[0]?.value,
              username: emails?.[0]?.value || `facebook_${id}`,
              displayName: `${name?.givenName} ${name?.familyName}`,
              photo: photos?.[0]?.value,
            });
            done(null, user);
          } catch (err) {
            done(err);
          }
        },
      );

      // Registrar dinámicamente en Passport
      const passport = (await import('passport')).default || (await import('passport'));
      passport.use('facebook', this.strategy);
    } catch (err: any) {
      if (err.code === 'MODULE_NOT_FOUND') {
        console.warn('passport-facebook no está instalado. Estrategia Facebook desactivada.');
      } else {
        console.error('Error cargando estrategia Facebook:', err);
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