// libs/auth/src/auth.module.ts
import { DynamicModule, Module, Provider } from '@nestjs/common';
import { AuthService } from './services/auth.service';

@Module({})
export class AuthModule {
  static forRoot(authServiceProvider: Provider): DynamicModule {
    return {
      module: AuthModule,
      providers: [authServiceProvider, { provide: AuthService, useExisting: authServiceProvider }],
      exports: [AuthService],
    };
  }
}