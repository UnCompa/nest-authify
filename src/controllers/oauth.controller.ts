import {
  Controller,
  Get,
  HttpStatus,
  Inject,
  Res,
  UseGuards
} from '@nestjs/common';
import {
  ApiExcludeEndpoint,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Response } from 'express';

import { AUTH_SERVICE } from '../constants';
import { CurrentUser } from '../decorators/current-user.decorator';
import { Public } from '../decorators/public.decorator';
import { FacebookAuthGuard } from '../guards/facebook-auth.guard';
import { GithubAuthGuard } from '../guards/github-auth.guard';
import { GoogleAuthGuard } from '../guards/google-auth.guard';
import { LoginResponse } from '../interfaces/auth-options.interface';
import { BaseAuthService } from '../services/base-auth.service';

/**
 * Controlador para autenticación OAuth
 * Soporta Google, Facebook y GitHub
 */
@ApiTags('OAuth')
@Controller('auth')
export class OAuthController {
  constructor(
    @Inject(AUTH_SERVICE)
    private readonly authService: BaseAuthService,
  ) { }

  // ==================== GOOGLE ====================

  /**
   * Inicia el flujo de autenticación con Google
   */
  @Public()
  @Get('google')
  @UseGuards(GoogleAuthGuard)
  @ApiOperation({
    summary: 'Login con Google',
    description: 'Redirige al usuario al flujo de autenticación de Google',
  })
  @ApiResponse({
    status: HttpStatus.FOUND,
    description: 'Redirección a Google OAuth',
  })
  async googleAuth(): Promise<void> {
    // Guard se encarga de la redirección
  }

  /**
   * Callback de Google OAuth
   */
  @Public()
  @Get('google/callback')
  @UseGuards(GoogleAuthGuard)
  @ApiExcludeEndpoint()
  async googleAuthCallback(
    @CurrentUser() user: any,
    @Res() res: Response,
  ): Promise<void> {
    const session = await this.authService.createSession(user, {
      provider: 'google',
    });

    // Redirigir al frontend con el token
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    res.redirect(
      `${frontendUrl}/auth/callback?token=${session.accessToken}&refresh=${session.refreshToken}`,
    );
  }

  /**
   * Endpoint alternativo para obtener los tokens después del callback
   */
  @Public()
  @Get('google/redirect')
  @UseGuards(GoogleAuthGuard)
  @ApiOperation({
    summary: 'Callback de Google (JSON)',
    description: 'Retorna los tokens en formato JSON en lugar de redireccionar',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Autenticación exitosa',
    schema: {
      type: 'object',
      properties: {
        accessToken: { type: 'string' },
        refreshToken: { type: 'string' },
        expiresIn: { type: 'number' },
        user: { type: 'object' },
      },
    },
  })
  async googleAuthRedirect(@CurrentUser() user: any): Promise<LoginResponse> {
    const session = await this.authService.createSession(user, {
      provider: 'google',
    });
    return {
      ...session,
      user: this.sanitizeUser(user),
    };
  }

  // ==================== FACEBOOK ====================

  /**
   * Inicia el flujo de autenticación con Facebook
   */
  @Public()
  @Get('facebook')
  @UseGuards(FacebookAuthGuard)
  @ApiOperation({
    summary: 'Login con Facebook',
    description: 'Redirige al usuario al flujo de autenticación de Facebook',
  })
  @ApiResponse({
    status: HttpStatus.FOUND,
    description: 'Redirección a Facebook OAuth',
  })
  async facebookAuth(): Promise<void> {
    // Guard se encarga de la redirección
  }

  /**
   * Callback de Facebook OAuth
   */
  @Public()
  @Get('facebook/callback')
  @UseGuards(FacebookAuthGuard)
  @ApiExcludeEndpoint()
  async facebookAuthCallback(
    @CurrentUser() user: any,
    @Res() res: Response,
  ): Promise<void> {
    const session = await this.authService.createSession(user, {
      provider: 'facebook',
    });

    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    res.redirect(
      `${frontendUrl}/auth/callback?token=${session.accessToken}&refresh=${session.refreshToken}`,
    );
  }

  /**
   * Endpoint alternativo para obtener los tokens después del callback
   */
  @Public()
  @Get('facebook/redirect')
  @UseGuards(FacebookAuthGuard)
  @ApiOperation({
    summary: 'Callback de Facebook (JSON)',
    description: 'Retorna los tokens en formato JSON en lugar de redireccionar',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Autenticación exitosa',
  })
  async facebookAuthRedirect(
    @CurrentUser() user: any,
  ): Promise<LoginResponse> {
    const session = await this.authService.createSession(user, {
      provider: 'facebook',
    });
    return {
      ...session,
      user: this.sanitizeUser(user),
    };
  }

  // ==================== GITHUB ====================

  /**
   * Inicia el flujo de autenticación con GitHub
   */
  @Public()
  @Get('github')
  @UseGuards(GithubAuthGuard)
  @ApiOperation({
    summary: 'Login con GitHub',
    description: 'Redirige al usuario al flujo de autenticación de GitHub',
  })
  @ApiResponse({
    status: HttpStatus.FOUND,
    description: 'Redirección a GitHub OAuth',
  })
  async githubAuth(): Promise<void> {
    // Guard se encarga de la redirección
  }

  /**
   * Callback de GitHub OAuth
   */
  @Public()
  @Get('github/callback')
  @UseGuards(GithubAuthGuard)
  @ApiExcludeEndpoint()
  async githubAuthCallback(
    @CurrentUser() user: any,
    @Res() res: Response,
  ): Promise<void> {
    const session = await this.authService.createSession(user, {
      provider: 'github',
    });

    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    res.redirect(
      `${frontendUrl}/auth/callback?token=${session.accessToken}&refresh=${session.refreshToken}`,
    );
  }

  /**
   * Endpoint alternativo para obtener los tokens después del callback
   */
  @Public()
  @Get('github/redirect')
  @UseGuards(GithubAuthGuard)
  @ApiOperation({
    summary: 'Callback de GitHub (JSON)',
    description: 'Retorna los tokens en formato JSON en lugar de redireccionar',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Autenticación exitosa',
  })
  async githubAuthRedirect(@CurrentUser() user: any): Promise<LoginResponse> {
    const session = await this.authService.createSession(user, {
      provider: 'github',
    });
    return {
      ...session,
      user: this.sanitizeUser(user),
    };
  }

  /**
   * Sanitiza el objeto de usuario eliminando campos sensibles
   */
  private sanitizeUser(user: any): any {
    const { password, ...sanitized } = user;
    return sanitized;
  }
}