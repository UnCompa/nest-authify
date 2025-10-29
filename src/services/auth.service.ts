import { Injectable, Inject, Optional } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

import { BaseAuthService } from './base-auth.service';
import { ISessionStore } from '../interfaces/session-store.interface';
import { IAuthRepository } from '../interfaces/auth-repository.interface';
import { HashService } from './hash.service';

/**
 * Implementación por defecto del servicio de autenticación
 * Extiende BaseAuthService y proporciona funcionalidad lista para usar
 */
@Injectable()
export class AuthService extends BaseAuthService {
  constructor(
    jwtService: JwtService,
    sessionStore: ISessionStore,
    hashService: HashService,
    @Optional() @Inject('AUTH_REPOSITORY') repository?: IAuthRepository,
    @Optional() configService?: ConfigService,
  ) {
    super(jwtService, sessionStore, hashService, repository, configService);
  }

  /**
   * Implementación de getUserById
   * Usa el repositorio si está disponible
   */
  protected async getUserById(userId: string): Promise<any> {
    if (!this.repository) {
      throw new Error('Auth repository not configured');
    }

    return this.repository.findUserById(userId);
  }

  /**
   * Método adicional: Obtener todas las sesiones activas de un usuario
   */
  async getUserActiveSessions(userId: string): Promise<any[]> {
    const sessions: any[] = [];
    // Implementación específica según el session store
    // Por ahora retorna array vacío
    return sessions;
  }

  /**
   * Método adicional: Verificar si un usuario tiene un rol específico
   */
  hasRole(user: any, role: string): boolean {
    return user.roles && user.roles.includes(role);
  }

  /**
   * Método adicional: Verificar si un usuario tiene un permiso específico
   */
  hasPermission(user: any, permission: string): boolean {
    return user.permissions && user.permissions.includes(permission);
  }

  /**
   * Método adicional: Actualizar información del usuario
   */
  async updateUserProfile(userId: string, data: Partial<any>): Promise<any> {
    if (!this.repository) {
      throw new Error('Auth repository not configured');
    }

    // No permitir actualizar password directamente
    const { password, ...updateData } = data;

    return this.repository.updateUser(userId, updateData);
  }

  /**
   * Método adicional: Desactivar cuenta de usuario
   */
  async deactivateUser(userId: string): Promise<void> {
    if (!this.repository) {
      throw new Error('Auth repository not configured');
    }

    await this.repository.updateUser(userId, { isActive: false });
    await this.revokeAllUserSessions(userId);
  }

  /**
   * Método adicional: Activar cuenta de usuario
   */
  async activateUser(userId: string): Promise<void> {
    if (!this.repository) {
      throw new Error('Auth repository not configured');
    }

    await this.repository.updateUser(userId, { isActive: true });
  }
}