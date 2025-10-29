import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsArray,
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  MinLength,
} from 'class-validator';

/**
 * DTO para login
 */
export class LoginRequestDto {
  @ApiPropertyOptional({
    description: 'Nombre de usuario',
    example: 'johndoe',
  })
  @IsOptional()
  @IsString()
  username?: string;

  @ApiPropertyOptional({
    description: 'Correo electrónico',
    example: 'john@example.com',
  })
  @IsOptional()
  @IsEmail()
  email?: string;

  @ApiProperty({
    description: 'Contraseña',
    example: 'MySecurePassword123!',
    minLength: 8,
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  password: string;
}

/**
 * DTO para registro
 */
export class RegisterRequestDto {
  @ApiPropertyOptional({
    description: 'Nombre de usuario',
    example: 'johndoe',
  })
  @IsOptional()
  @IsString()
  username?: string;

  @ApiProperty({
    description: 'Correo electrónico',
    example: 'john@example.com',
  })
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'Contraseña',
    example: 'MySecurePassword123!',
    minLength: 8,
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  password: string;

  @ApiPropertyOptional({
    description: 'Nombre completo',
    example: 'John Doe',
  })
  @IsOptional()
  @IsString()
  fullName?: string;

  @ApiPropertyOptional({
    description: 'Roles del usuario',
    example: ['user'],
    type: [String],
  })
  @IsOptional()
  @IsArray()
  roles?: string[];
}

/**
 * DTO para refresh token
 */
export class RefreshTokenDto {
  @ApiProperty({
    description: 'Refresh token',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  @IsNotEmpty()
  @IsString()
  refreshToken: string;
}


/**
 * DTO de perfil de usuario
 */
export class UserProfileDto {
  @ApiProperty({
    description: 'ID del usuario',
    example: '507f1f77bcf86cd799439011',
  })
  id: string;

  @ApiPropertyOptional({
    description: 'Nombre de usuario',
    example: 'johndoe',
  })
  username?: string;

  @ApiPropertyOptional({
    description: 'Correo electrónico',
    example: 'john@example.com',
  })
  email?: string;

  @ApiPropertyOptional({
    description: 'Nombre completo',
    example: 'John Doe',
  })
  fullName?: string;

  @ApiPropertyOptional({
    description: 'Roles del usuario',
    example: ['user', 'admin'],
    type: [String],
  })
  roles?: string[];

  @ApiPropertyOptional({
    description: 'Permisos del usuario',
    example: ['read:posts', 'write:posts'],
    type: [String],
  })
  permissions?: string[];

  @ApiPropertyOptional({
    description: 'Proveedor OAuth',
    example: 'google',
    enum: ['local', 'google', 'facebook', 'github'],
  })
  provider?: string;

  @ApiPropertyOptional({
    description: 'Estado de la cuenta',
    example: true,
  })
  isActive?: boolean;

  @ApiPropertyOptional({
    description: 'Fecha de creación',
    example: '2024-01-15T10:30:00.000Z',
  })
  createdAt?: Date;

  @ApiPropertyOptional({
    description: 'Última actualización',
    example: '2024-01-20T15:45:00.000Z',
  })
  updatedAt?: Date;
}


/**
 * DTO de respuesta de login
 */
export class LoginResponseDto {
  @ApiProperty({
    description: 'Access token JWT',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  accessToken: string;

  @ApiProperty({
    description: 'Refresh token JWT',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  refreshToken: string;

  @ApiProperty({
    description: 'Tiempo de expiración en segundos',
    example: 3600,
  })
  expiresIn: number;

  @ApiProperty({
    description: 'Tipo de token',
    example: 'Bearer',
  })
  tokenType: string;

  @ApiProperty({
    description: 'ID del usuario',
    example: '507f1f77bcf86cd799439011',
  })
  sub: string;

  @ApiProperty({
    description: 'ID de la sesión',
    example: 'sess_507f1f77bcf86cd799439011',
  })
  sessionId: string;

  @ApiProperty({
    description: 'Datos del usuario',
  })
  user: UserProfileDto;
}

/**
 * DTO para cambiar contraseña
 */
export class ChangePasswordDto {
  @ApiProperty({
    description: 'Contraseña actual',
    example: 'OldPassword123!',
  })
  @IsNotEmpty()
  @IsString()
  oldPassword: string;

  @ApiProperty({
    description: 'Nueva contraseña',
    example: 'NewSecurePassword123!',
    minLength: 8,
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  newPassword: string;
}

/**
 * DTO para recuperación de contraseña
 */
export class ForgotPasswordDto {
  @ApiProperty({
    description: 'Correo electrónico',
    example: 'john@example.com',
  })
  @IsNotEmpty()
  @IsEmail()
  email: string;
}

/**
 * DTO para reset de contraseña
 */
export class ResetPasswordDto {
  @ApiProperty({
    description: 'Token de reset',
    example: 'reset_token_here',
  })
  @IsNotEmpty()
  @IsString()
  token: string;

  @ApiProperty({
    description: 'Nueva contraseña',
    example: 'NewSecurePassword123!',
    minLength: 8,
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  newPassword: string;
}