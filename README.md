# @uncompadev/auth-validation

Una librería para validar tokens JWT en aplicaciones NestJS.

## Instalación

Instala el paquete desde npm con el siguiente comando:

```bash
npm install @uncompadev/auth-validation
```

## Uso

### En el servicio de autenticación

Genera un token JWT usando el paquete:

```typescript
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { TokenPayload } from '@uncompadev/auth-validation';

@Injectable()
export class AuthService {
  constructor(private readonly jwtService: JwtService) {}

  generateToken(userId: string, roles: string[]): string {
    const payload: TokenPayload = { sub: userId, roles };
    return this.jwtService.sign(payload);
  }
}
```

### En los servicios consumidores

Protege tus rutas y accede a los datos del token:

```typescript
import { Controller, Get, Req } from '@nestjs/common';
import { Auth, TokenPayload } from '@uncompadev/auth-validation';

@Controller('users')
export class UsersController {
  @Auth({ roles: ['admin'] })
  @Get()
  findAll(@Req() req: { user: TokenPayload }) {
    const user = req.user;
    return `Hello, ${user.sub}!`;
  }
}
```

## Configuración

Configura el `JwtModule` en tu aplicación NestJS con una clave secreta:

```typescript
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
    JwtModule.register({
      secret: 'tu-clave-secreta',
      signOptions: { expiresIn: '60m' },
    }),
  ],
})
export class AppModule {}
```

## Contribución

¡Las contribuciones son bienvenidas! Por favor, abre un issue o envía un pull request en el repositorio.

## Licencia

Distribuido bajo la licencia MIT.