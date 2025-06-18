// libs/auth/src/auth.module.ts
import { DynamicModule, Module, Provider, Type } from '@nestjs/common';
import { AuthService } from './services/auth.service';

@Module({})
export class AuthorizationModule {
  static forRoot(authServiceProvider: Provider | Type<any>): DynamicModule {
    // Handle both Provider and Type<any>
    const provider: Provider = this.normalizeProvider(authServiceProvider);

    return {
      module: AuthorizationModule,
      providers: [provider, { provide: AuthService, useExisting: (provider as any).provide || provider }],
      exports: [AuthService],
    };
  }

  private static normalizeProvider(authServiceProvider: Provider | Type<any>): Provider {
    // If it's a class (Type<any>), convert it to a ClassProvider
    if (typeof authServiceProvider === 'function') {
      return {
        provide: AuthService,
        useClass: authServiceProvider,
      };
    }
    // Otherwise, assume it's a valid Provider (e.g., ClassProvider)
    return authServiceProvider;
  }
}