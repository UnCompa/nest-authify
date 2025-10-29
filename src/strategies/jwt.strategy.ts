import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AUTH_SERVICE } from '../constants';
import { JwtPayload } from '../interfaces/auth-options.interface';
import { BaseAuthService } from '../services/base-auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    @Inject(AUTH_SERVICE) private authService: BaseAuthService,
    private configService: ConfigService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET'),
      passReqToCallback: true,
    });
  }

  async validate(req: Request, payload: JwtPayload): Promise<any> {
    const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);
    if (!token) throw new UnauthorizedException('No token provided');

    const validPayload = await this.authService.verifyToken(token);

    return {
      id: validPayload.sub,
      username: validPayload.username,
      email: validPayload.email,
      roles: validPayload.roles || [],
      permissions: validPayload.permissions || [],
      sessionId: validPayload.sessionId,
    };
  }
}