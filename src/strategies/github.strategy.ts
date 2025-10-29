// src/strategies/github.strategy.ts

import { Injectable } from '@nestjs/common';
import { IAuthService } from '../core/interfaces/auth-service.interface';
import { ProvidersAuth } from '../core/types/auth-session.interface';
import { GithubOAuthConfig } from '../interfaces/auth-options.interface';

@Injectable()
export class GithubStrategy {
  private strategy: any = null;

  constructor(
    private readonly authService: IAuthService,
    private readonly config: GithubOAuthConfig,
  ) {
    this.init();
  }

  private async init() {
    try {
      const { Strategy } = await import('passport-github2');

      this.strategy = new Strategy(
        {
          clientID: this.config.clientId,
          clientSecret: this.config.clientSecret,
          callbackURL: this.config.callbackUrl || 'http://localhost:3000/auth/github/callback',
          scope: this.config.scope || ['user:email'],
        },
        async (accessToken: string, refreshToken: string, profile: any, done: any) => {
          try {
            const user = await this.authService.validateOAuthUser(profile, ProvidersAuth.GITHUB);
            done(null, user);
          } catch (err) {
            done(err);
          }
        },
      );

      const passport = (await import('passport')).default || (await import('passport'));
      passport.use('github', this.strategy);
    } catch (err: any) {
      if (err.code === 'MODULE_NOT_FOUND') {
        console.warn('passport-github2 no instalado. GitHub OAuth desactivado.');
      } else {
        console.error('Error cargando GitHub Strategy:', err);
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