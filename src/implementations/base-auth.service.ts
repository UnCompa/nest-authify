import { Injectable, Inject, Optional } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { randomBytes } from 'crypto';
import { ISessionStore } from '../core/interfaces/session-store.interface';
import { AuthSession, JwtPayload, RefreshTokenPayload } from '../core/types/auth-session.interface';

@Injectable()
export abstract class BaseAuthService {
  constructor(
    protected readonly jwtService: JwtService,
    @Optional() @Inject('SESSION_STORE') protected readonly sessionStore?: ISessionStore,
  ) { }

  protected generateSessionId(): string {
    return randomBytes(32).toString('hex');
  }

  async createJwt(user: any, expiresIn = '60m', sessionId?: string): Promise<string> {
    const payload: JwtPayload = {
      sub: user.id,
      roles: user.roles,
      type: 'access',
      sessionId: sessionId || this.generateSessionId(),
    };
    return this.jwtService.sign(payload, { expiresIn });
  }

  async createRefreshToken(user: any, expiresIn = '7d', sessionId?: string): Promise<string> {
    const payload: RefreshTokenPayload = {
      sub: user.id,
      type: 'refresh',
      sessionId: sessionId || this.generateSessionId(),
    };
    return this.jwtService.sign(payload, { expiresIn });
  }

  async createSession(user: any, options?: any): Promise<AuthSession> {
    const sessionId = this.generateSessionId();
    const accessToken = await this.createJwt(user, options?.jwtExpiresIn, sessionId);
    const refreshToken = await this.createRefreshToken(user, options?.refreshExpiresIn, sessionId);

    const session: AuthSession = {
      sub: user.id,
      roles: user.roles,
      accessToken,
      refreshToken,
      provider: options?.provider,
      providerData: options?.providerData,
      sessionId,
    };

    // Guardar sesión en store si está disponible
    if (this.sessionStore) {
      const ttl = this.parseTTL(options?.refreshExpiresIn || '7d');
      await this.sessionStore.set(
        `session:${sessionId}`,
        { userId: user.id, roles: user.roles, createdAt: Date.now() },
        ttl,
      );
    }

    return session;
  }

  async verifyToken(token: string): Promise<JwtPayload> {
    const payload = await this.jwtService.verifyAsync<JwtPayload>(token);

    // Verificar si la sesión sigue activa (si hay session store)
    if (this.sessionStore && payload.sessionId) {
      const sessionExists = await this.sessionStore.exists(`session:${payload.sessionId}`);
      if (!sessionExists) {
        throw new Error('Session expired or invalid');
      }
    }

    return payload;
  }

  async refreshAccessToken(refreshToken: string): Promise<{ accessToken: string }> {
    const payload = await this.verifyToken(refreshToken);

    if (payload.type !== 'refresh') {
      throw new Error('Invalid token type');
    }

    const user = await this.getUserById(payload.sub);

    if (!user) {
      throw new Error('User not found');
    }

    const accessToken = await this.createJwt(
      { id: user.id, roles: user.roles },
      '60m',
      payload.sessionId,
    );

    return { accessToken };
  }

  async revokeSession(sessionId: string): Promise<void> {
    if (this.sessionStore) {
      await this.sessionStore.delete(`session:${sessionId}`);
    }
  }

  async revokeAllUserSessions(userId: string): Promise<void> {
    // Esta funcionalidad requiere un índice adicional en el store
    // Por ahora es básica, pero puede extenderse
    if (this.sessionStore) {
      // Implementación depende del store concreto
      console.warn('revokeAllUserSessions requires custom implementation');
    }
  }

  private parseTTL(duration: string): number {
    const match = duration.match(/^(\d+)([smhd])$/);
    if (!match) return 604800; // 7 días por defecto

    const value = parseInt(match[1]);
    const unit = match[2];

    const multipliers: Record<string, number> = {
      s: 1,
      m: 60,
      h: 3600,
      d: 86400,
    };

    return value * multipliers[unit];
  }

  protected abstract getUserById(userId: string): Promise<any>;
}