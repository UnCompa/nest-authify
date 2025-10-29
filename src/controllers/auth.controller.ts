import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Post,
  UnauthorizedException
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';

import { AUTH_SERVICE } from '../constants';
import { CurrentUser } from '../decorators/current-user.decorator';
import { Public } from '../decorators/public.decorator';
import { SessionId } from '../decorators/session-id.decorator';
import {
  ChangePasswordDto,
  LoginRequestDto,
  LoginResponseDto,
  RefreshTokenDto,
  RegisterRequestDto,
  UserProfileDto,
} from '../dto/auth.dto';
import { LoginResponse } from '../interfaces/auth-options.interface';
import { BaseAuthService } from '../services/base-auth.service';

/**
 * Controlador de autenticación con endpoints listos para usar
 * Documentado con Swagger
 */
@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(
    @Inject(AUTH_SERVICE)
    private readonly authService: BaseAuthService,
  ) { }

  /**
   * Registro de nuevos usuarios
   */
  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Registrar nuevo usuario',
    description: 'Crea una nueva cuenta de usuario en el sistema',
  })
  @ApiBody({ type: RegisterRequestDto })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'Usuario registrado exitosamente',
    type: LoginResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Datos de registro inválidos',
  })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'El usuario ya existe',
  })
  async register(
    @Body() registerDto: RegisterRequestDto,
  ): Promise<LoginResponse> {
    const user = await this.authService.register(registerDto);
    const session = await this.authService.createSession(user);
    return {
      ...session,
      user: this.sanitizeUser(user),
    };
  }

/**
 * Login con credenciales locales
 */
@Public()
@Post('login')
@HttpCode(HttpStatus.OK)
@ApiOperation({
  summary: 'Iniciar sesión',
  description: 'Autenticación con username/email y contraseña',
})
@ApiBody({ type: LoginRequestDto })
@ApiResponse({
  status: HttpStatus.OK,
  description: 'Login exitoso',
  type: LoginResponseDto,
})
@ApiResponse({
  status: HttpStatus.UNAUTHORIZED,
  description: 'Credenciales inválidas',
})
@ApiResponse({
  status: HttpStatus.BAD_REQUEST,
  description: 'Debe proporcionar username o email',
})
async login(
  @Body() loginDto: LoginRequestDto,
): Promise<LoginResponse> {
  // Validar que se proporcione username o email
  if (!loginDto.username && !loginDto.email) {
    throw new BadRequestException('Username or email is required');
  }

  // Usar email o username para la validación
  const identifier = loginDto.email || loginDto.username;

  // Validar credenciales
  const user = await this.authService.validateUser(
    identifier,
    loginDto.password,
  );

  if (!user) {
    throw new UnauthorizedException('Invalid credentials');
  }

  // Verificar si el usuario está activo
  if (!user.isActive) {
    throw new UnauthorizedException('User account is inactive');
  }

  // Crear sesión
  const session = await this.authService.createSession(user);

  return {
    ...session,
    user: this.sanitizeUser(user),
  };
}

  /**
   * Obtener perfil del usuario autenticado
   */
  @Get('profile')
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Obtener perfil',
    description: 'Retorna el perfil del usuario autenticado',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Perfil del usuario',
    type: UserProfileDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'No autenticado',
  })
  async getProfile(@CurrentUser() user: any): Promise<UserProfileDto> {
    return this.sanitizeUser(user);
  }

  /**
   * Refrescar access token
   */
  @Public()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Refrescar token',
    description: 'Genera un nuevo access token usando el refresh token',
  })
  @ApiBody({ type: RefreshTokenDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Token refrescado exitosamente',
    schema: {
      type: 'object',
      properties: {
        accessToken: { type: 'string' },
        expiresIn: { type: 'number' },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Refresh token inválido o expirado',
  })
  async refresh(
    @Body() refreshDto: RefreshTokenDto,
  ): Promise<{ accessToken: string; expiresIn: number }> {
    return this.authService.refreshAccessToken(refreshDto.refreshToken);
  }

  /**
   * Cerrar sesión actual
   */
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Cerrar sesión',
    description: 'Revoca la sesión actual del usuario',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Sesión cerrada exitosamente',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'No autenticado',
  })
  async logout(@SessionId() sessionId: string): Promise<{ message: string }> {
    if (!sessionId) {
      throw new BadRequestException('Session ID not found');
    }
    await this.authService.revokeSession(sessionId);
    return { message: 'Logged out successfully' };
  }

  /**
   * Cerrar todas las sesiones del usuario
   */
  @Post('logout-all')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Cerrar todas las sesiones',
    description: 'Revoca todas las sesiones activas del usuario',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Todas las sesiones cerradas exitosamente',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'No autenticado',
  })
  async logoutAll(
    @CurrentUser('id') userId: string,
  ): Promise<{ message: string }> {
    if (!userId) {
      throw new BadRequestException('User ID not found');
    }
    await this.authService.revokeAllUserSessions(userId);
    return { message: 'All sessions revoked successfully' };
  }

  /**
   * Verificar si el token es válido
   */
  @Get('verify')
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Verificar token',
    description: 'Verifica si el token actual es válido',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Token válido',
    schema: {
      type: 'object',
      properties: {
        valid: { type: 'boolean' },
        user: { $ref: '#/components/schemas/UserProfileDto' },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Token inválido',
  })
  async verifyToken(
    @CurrentUser() user: any,
  ): Promise<{ valid: boolean; user: UserProfileDto }> {
    return {
      valid: true,
      user: this.sanitizeUser(user),
    };
  }

  /**
   * Cambiar contraseña
   */
  @Post('change-password')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Cambiar contraseña',
    description: 'Cambia la contraseña del usuario autenticado',
  })
  @ApiBody({ type: ChangePasswordDto })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Contraseña cambiada exitosamente',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Contraseña antigua incorrecta',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'No autenticado',
  })
  async changePassword(
    @CurrentUser('id') userId: string,
    @Body() changePasswordDto: ChangePasswordDto,
  ): Promise<{ message: string }> {
    if (!userId) {
      throw new BadRequestException('User ID not found');
    }

    await this.authService.changePassword(
      userId,
      changePasswordDto.oldPassword,
      changePasswordDto.newPassword,
    );

    return { message: 'Password changed successfully' };
  }

  /**
   * Actualizar perfil del usuario
   */
  @Post('update-profile')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Actualizar perfil',
    description: 'Actualiza la información del perfil del usuario autenticado',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        fullName: { type: 'string' },
        username: { type: 'string' },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Perfil actualizado exitosamente',
    type: UserProfileDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'No autenticado',
  })
  async updateProfile(
    @CurrentUser('id') userId: string,
    @Body() updateData: Partial<any>,
  ): Promise<UserProfileDto> {
    if (!userId) {
      throw new BadRequestException('User ID not found');
    }

    // No permitir actualizar campos sensibles
    const { password, roles, permissions, isActive, ...safeData } = updateData;

    const updatedUser = await this.authService.updateUserProfile(
      userId,
      safeData,
    );

    return this.sanitizeUser(updatedUser);
  }

  /**
   * Obtener información de sesión actual
   */
  @Get('session')
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Información de sesión',
    description: 'Obtiene información sobre la sesión actual',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Información de la sesión',
    schema: {
      type: 'object',
      properties: {
        sessionId: { type: 'string' },
        userId: { type: 'string' },
        username: { type: 'string' },
        roles: { type: 'array', items: { type: 'string' } },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'No autenticado',
  })
  async getSession(
    @CurrentUser() user: any,
    @SessionId() sessionId: string,
  ): Promise<{
    sessionId: string;
    userId: string;
    username?: string;
    email?: string;
    roles: string[];
  }> {
    return {
      sessionId: sessionId || 'unknown',
      userId: user.id,
      username: user.username,
      email: user.email,
      roles: user.roles || [],
    };
  }

  /**
   * Sanitiza el objeto de usuario eliminando campos sensibles
   */
  private sanitizeUser(user: any): UserProfileDto {
    if (!user) return user;

    const { password, ...sanitized } = user;
    return sanitized;
  }
}