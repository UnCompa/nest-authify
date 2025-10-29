import { BadRequestException, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';

import {
  AuthSession,
  AuthUser,
  CreateSessionOptions,
  JwtPayload,
  RegisterUserDto,
  ValidatedUser,
} from '../interfaces/auth-options.interface';
import { IAuthRepository } from '../interfaces/auth-repository.interface';
import { ISessionStore } from '../interfaces/session-store.interface';
import { HashService } from './hash.service';

/**
 * Servicio base de autenticación
 * Extender esta clase para personalizar el comportamiento
 */
@Injectable()
export abstract class BaseAuthService {
  private readonly logger = new Logger("NestAuthify");
  private readonly debugEnabled: boolean;
  constructor(
    protected readonly jwtService: JwtService,
    protected readonly sessionStore: ISessionStore,
    protected readonly hashService: HashService,
    protected readonly repository?: IAuthRepository,
    protected readonly configService?: ConfigService,
  ) {
    this.debugEnabled = !!(this.configService?.get('AUTHIFY_DEBUG') === 'true');
  }

  /**
   * Crea un JWT access token
   */
  async createJwt(
    user: any,
    expiresIn?: string,
    sessionId?: string,
  ): Promise<string> {
    if (this.debugEnabled) {
      this.logger.debug('🔑 Creando JWT', { userId: user.id, expiresIn, sessionId: sessionId || 'nuevo' });
    }
    const payload: JwtPayload = {
      sub: user.id,
      username: user.username,
      email: user.email,
      roles: user.roles || [],
      permissions: user.permissions || [],
      sessionId: sessionId || uuidv4(),
    };

    if (this.debugEnabled) {
      this.logger.debug('✅ JWT creado exitosamente');
    }

    return this.jwtService.signAsync(payload, {
      expiresIn: expiresIn || this.configService?.get('JWT_EXPIRES_IN', '60m'),
    });
  }

  /**
   * Crea un refresh token
   */
  async createRefreshToken(
    user: any,
    expiresIn?: string,
    sessionId?: string,
  ): Promise<string> {
    if (this.debugEnabled) {
      this.logger.debug('🔄 Creando refresh token', { userId: user.id, expiresIn });
    }
    const payload: JwtPayload = {
      sub: user.id,
      sessionId: sessionId || uuidv4(),
    };

    const token = await this.jwtService.signAsync(payload, {
      expiresIn: expiresIn || this.configService?.get('REFRESH_EXPIRES_IN', '7d'),
    });

    if (this.debugEnabled) {
      this.logger.debug('✅ Refresh token creado');
    }

    return token;
  }

  /**
   * Crea una sesión completa con access y refresh tokens
   */
  async createSession(
    user: any,
    options?: CreateSessionOptions,
  ): Promise<AuthSession> {
    if (this.debugEnabled) {
      this.logger.debug('🎯 Iniciando creación de sesión', { userId: user.id, provider: options?.provider || 'local' });
    }
    const sessionId = uuidv4();
    const accessToken = await this.createJwt(
      user,
      options?.expiresIn,
      sessionId,
    );
    const refreshToken = await this.createRefreshToken(
      user,
      options?.refreshExpiresIn,
      sessionId,
    );

    // Almacenar sesión
    const sessionData = {
      userId: user.id,
      sessionId,
      createdAt: new Date().toISOString(),
      provider: options?.provider || 'local',
      metadata: options?.metadata || {},
    };

    const ttl = this.parseDuration(
      options?.refreshExpiresIn ||
      this.configService?.get('REFRESH_EXPIRES_IN', '7d'),
    );
    if (this.debugEnabled) {
      this.logger.debug('💾 Guardando sesión en store', { sessionId, ttl: `${ttl}s`, key: `session:${sessionId}` });
    }
    await this.sessionStore.set(`session:${sessionId}`, sessionData, ttl);

    // Calcular expiresIn en segundos
    const expiresIn = this.parseDuration(
      options?.expiresIn || this.configService?.get('JWT_EXPIRES_IN', '60m'),
    );

    if (this.debugEnabled) {
      this.logger.debug('✅ Sesión creada y guardada');
    }

    return {
      accessToken,
      refreshToken,
      expiresIn,
      tokenType: 'Bearer',
      sub: user.id,
      sessionId,
      ...options?.metadata,
    };
  }

  /**
   * Verifica y decodifica un token
   */
  async verifyToken(token: string): Promise<JwtPayload> {
    if (this.debugEnabled) {
      this.logger.debug('🔍 Verificando token');
    }
    try {

      const payload = await this.jwtService.verifyAsync<JwtPayload>(token);
      if (this.debugEnabled) {
        this.logger.debug('✅ Token verificado', {
          userId: payload.sub,
          sessionId: payload.sessionId?.substring(0, 8) + '...'
        });
      }
      // Verificar si la sesión existe
      if (payload.sessionId) {
        const sessionExists = await this.sessionStore.exists(
          `session:${payload.sessionId}`,
        );

        if (!sessionExists) {
          if (this.debugEnabled) {
            this.logger.debug('❌ Sesión revocada');
          }
          throw new UnauthorizedException('Session has been revoked');
        }
        if (this.debugEnabled) {
          this.logger.debug('✅ Sesión válida');
        }
      }

      return payload;
    } catch (error) {
      console.error(error);
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  /**
   * Refresca un access token usando un refresh token
   */
  async refreshAccessToken(
    refreshToken: string,
  ): Promise<{ accessToken: string; expiresIn: number }> {
    try {
      if (this.debugEnabled) {
        this.logger.debug('🔄 Refrescando access token');
      }
      const payload = await this.jwtService.verifyAsync<JwtPayload>(
        refreshToken,
      );

      // Verificar si la sesión existe
      if (payload.sessionId) {
        const sessionExists = await this.sessionStore.exists(
          `session:${payload.sessionId}`,
        );
        if (!sessionExists) {
          throw new UnauthorizedException('Session has been revoked');
        }
      }

      // Obtener usuario actualizado
      const user = await this.getUserById(payload.sub);
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Crear nuevo access token
      const accessToken = await this.createJwt(user, undefined, payload.sessionId);
      const expiresIn = this.parseDuration(
        this.configService?.get('JWT_EXPIRES_IN', '60m'),
      );

      if (this.debugEnabled) {
        this.logger.debug('✅ Access token refrescado', { userId: user.id });
      }

      return { accessToken, expiresIn };
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  /**
   * Revoca una sesión específica
   */
  async revokeSession(sessionId: string): Promise<void> {
    if (this.debugEnabled) {
      this.logger.debug('🗑️ Revocando sesión', { sessionId: sessionId.substring(0, 8) + '...' });
    }
    await this.sessionStore.delete(`session:${sessionId}`);
    if (this.debugEnabled) {
      this.logger.debug('✅ Sesión revocada');
    }
  }

  /**
   * Revoca todas las sesiones de un usuario
   */
  async revokeAllUserSessions(userId: string): Promise<void> {
    if (this.debugEnabled) {
      this.logger.debug('🗑️ Revocando TODAS las sesiones del usuario', { userId });
    }
    // Buscar todas las sesiones del usuario
    const keys = await this.getAllSessionKeys();
    for (const key of keys) {
      const session = await this.sessionStore.get(key);
      if (session && session.userId === userId) {
        await this.sessionStore.delete(key);
      }
    }
    if (this.debugEnabled) {
      this.logger.debug('✅ Todas las sesiones revocadas');
    }
  }

  /**
   * Registra un nuevo usuario
   */
  async register(data: RegisterUserDto): Promise<any> {

    if (!this.repository) {
      throw new Error('Auth repository not configured');
    }
    if (this.debugEnabled) {
      this.logger.debug('📝 Registrando nuevo usuario', { email: data.email });
    }

    // Verificar si el usuario ya existe
    const existingUser = data.email
      ? await this.repository.findUserByUsername(data.email)
      : null;
    if (existingUser) {
      throw new BadRequestException('User already exists');
    }

    // Hash de contraseña
    const hashedPassword = await this.hashService.hash(data.password);

    // Crear usuario
    const user = await this.repository.createUser({
      ...data,
      password: hashedPassword,
      roles: data.roles || ['user'],
      isActive: true,
      provider: 'local',
    });

    if (this.debugEnabled) {
      this.logger.debug('✅ Usuario registrado', { userId: user.id });
    }

    return user;
  }

  /**
 * Actualiza el perfil del usuario excluyendo campos sensibles
 */
  async updateUserProfile(userId: string, data: Partial<any>): Promise<any> {
    if (!this.repository) {
      throw new Error('Auth repository not configured');
    }

    // Validar que el usuario existe
    const user = await this.repository.findUserById(userId);
    if (!user) {
      throw new BadRequestException('User not found');
    }

    // Actualizar solo los campos permitidos
    const updatedUser = await this.repository.updateUser(userId, data);

    // Devolver usuario sin campos sensibles
    const { password, ...safeUser } = updatedUser;
    return safeUser;
  }

  /**
   * Valida las credenciales del usuario
   */
  /**
 * Valida las credenciales del usuario
 * Detecta automáticamente si el identificador es email o username
 */
  async validateUser(
    identifier: string,
    password: string,
  ): Promise<ValidatedUser | null> {
    if (!this.repository) {
      throw new Error('Auth repository not configured');
    }

    if (this.debugEnabled) {
      this.logger.debug('🔐 Validando usuario', { identifier: identifier.substring(0, 20) + '...' });
    }



    // Detectar si el identificador es un email
    const isEmail = this.isValidEmail(identifier);

    let user: AuthUser | null = null;

    if (isEmail) {
      user = await this.repository.findUserByEmail(identifier);
    } else {
      user = await this.repository.findUserByUsername(identifier);
    }

    if (!user) {
      this.logger.error('User not found');
      return null;
    }

    if (this.debugEnabled) {
      this.logger.debug('👤 Usuario encontrado', { id: user.id, active: user.isActive });
    }


    // Validar contraseña
    const isPasswordValid = await this.hashService.verify(
      password,
      user.password,
    );

    if (!isPasswordValid) {
      console.info('Invalid password');
      return null;
    }

    if (this.debugEnabled) {
      this.logger.debug('✅ Usuario validado correctamente');
    }

    // Retornar usuario sin el password
    const { password: _, ...result } = user;
    return result;
  }

  /**
   * Valida si una cadena tiene formato de email
   */
  private isValidEmail(identifier: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(identifier);
  }

  /**
   * Valida usuario OAuth
   */
  async validateOAuthUser(
    provider: string,
    providerId: string,
    profile: any,
  ): Promise<any> {
    if (!this.repository) {
      throw new Error('Auth repository not configured');
    }

    // Buscar usuario existente
    let user = await this.repository.findUserByProviderId(provider, providerId);

    if (!user) {
      // Crear nuevo usuario
      user = await this.repository.createUser({
        email: profile.email,
        username: profile.username || profile.email,
        fullName: profile.displayName || profile.name,
        provider,
        providerId,
        isActive: true,
        roles: ['user'],
      });
    }

    return user;
  }

  /**
   * Cambia la contraseña de un usuario
   */
  async changePassword(
    userId: string,
    oldPassword: string,
    newPassword: string,
  ): Promise<void> {
    if (!this.repository) {
      throw new Error('Auth repository not configured');
    }

    const user = await this.repository.findUserById(userId);
    if (!user) {
      throw new BadRequestException('User not found');
    }
    const isOldPasswordValid = await this.hashService.verify(
      oldPassword,
      user.password,
    );
    if (!isOldPasswordValid) {
      throw new BadRequestException('Invalid old password');
    }

    const hashedPassword = await this.hashService.hash(newPassword);
    await this.repository.updateUser(userId, { password: hashedPassword });

    // Revocar todas las sesiones
    await this.revokeAllUserSessions(userId);
  }

  /**
   * Obtiene usuario por ID - debe ser implementado por clases hijas
   */
  protected abstract getUserById(userId: string): Promise<any>;

  /**
   * Obtiene todas las claves de sesión
   */
  private async getAllSessionKeys(): Promise<string[]> {
    // Esto depende de la implementación del session store
    // Para Redis, usaríamos SCAN
    // Para memoria, iteraríamos sobre el Map
    return [];
  }

  /**
   * Convierte una duración string a segundos
   */
  private parseDuration(duration: string): number {
    const match = duration.match(/^(\d+)([smhd])$/);
    if (!match) return 3600; // 1 hour por defecto

    const value = parseInt(match[1]);
    const unit = match[2];

    switch (unit) {
      case 's':
        return value;
      case 'm':
        return value * 60;
      case 'h':
        return value * 3600;
      case 'd':
        return value * 86400;
      default:
        return 3600;
    }
  }
}