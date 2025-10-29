import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { HashCallback, HashVerifyCallback } from '../interfaces/auth-options.interface';

/**
 * Servicio para hash y verificación de contraseñas
 * Soporta callbacks personalizados o usa bcrypt por defecto
 */
@Injectable()
export class HashService {
  private readonly saltRounds = 10;

  constructor(
    private readonly hashCallback?: HashCallback,
    private readonly verifyCallback?: HashVerifyCallback,
  ) { }

  /**
   * Hashea una contraseña
   */
  async hash(password: string): Promise<string> {
    if (this.hashCallback) {
      return this.hashCallback(password);
    }

    // Implementación por defecto con bcrypt
    return bcrypt.hash(password, this.saltRounds);
  }

  /**
   * Verifica una contraseña contra un hash
   */
  async verify(password: string, hash: string): Promise<boolean> {
    if (this.verifyCallback) {
      return this.verifyCallback(password, hash);
    }

    // Implementación por defecto con bcrypt
    return bcrypt.compare(password, hash);
  }

  /**
   * Genera un hash aleatorio (útil para tokens)
   */
  async generateRandomHash(length: number = 32): Promise<string> {
    const randomBytes = require('crypto').randomBytes(length);
    return randomBytes.toString('hex');
  }

  /**
   * Verifica la fortaleza de una contraseña
   */
  isPasswordStrong(password: string): boolean {
    // Al menos 8 caracteres
    if (password.length < 8) return false;

    // Al menos una mayúscula
    if (!/[A-Z]/.test(password)) return false;

    // Al menos una minúscula
    if (!/[a-z]/.test(password)) return false;

    // Al menos un número
    if (!/\d/.test(password)) return false;

    // Al menos un carácter especial
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) return false;

    return true;
  }
}