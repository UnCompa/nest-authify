import { Inject, Injectable, Optional } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { IAuthRepository } from '../core/interfaces/auth-repository.interface';
import { ISessionStore } from '../core/interfaces/session-store.interface';
import { OAuthProfile, ProvidersAuth } from '../core/types/auth-session.interface';
import { BaseAuthService } from './base-auth.service';

@Injectable()
export class DefaultAuthService extends BaseAuthService {
  constructor(
    jwtService: JwtService,
    @Inject('AUTH_REPOSITORY') private readonly authRepository: IAuthRepository,
    @Optional() @Inject('SESSION_STORE') sessionStore?: ISessionStore,
  ) {
    super(jwtService, sessionStore);
  }

  async validateUser(username: string, password: string) {
    const user = await this.authRepository.findUserByUsername(username);
    if (user && await bcrypt.compare(password, user.password)) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async validateOAuthUser(profile: OAuthProfile, provider: ProvidersAuth) {
    const email = profile.emails?.[0]?.value;
    if (!email) {
      throw new Error('Email not provided by OAuth provider');
    }

    // Buscar por provider y providerId primero
    let user = await this.authRepository.findUserByProviderId(provider, profile.id);

    // Si no existe, buscar por email
    if (!user) {
      user = await this.authRepository.findUserByUsername(email);
    }

    // Si no existe, crear usuario
    if (!user) {
      user = await this.authRepository.createUser({
        username: email,
        email,
        provider,
        providerId: profile.id,
        displayName: profile.displayName,
        firstName: profile.name?.givenName,
        lastName: profile.name?.familyName,
        avatar: profile.photos?.[0]?.value,
      });
    } else if (!user.providerId) {
      // Vincular cuenta existente con OAuth
      user = await this.authRepository.updateUser(user.id, {
        provider,
        providerId: profile.id,
      });
    }

    return user;
  }

  protected async getUserById(userId: string) {
    return this.authRepository.findUserById(userId);
  }
}
