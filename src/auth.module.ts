// libs/auth/src/auth.module.ts
import { DynamicModule, Module, Provider, Type } from '@nestjs/common';
import { AuthService } from './services/auth.service';

@Module({})
export class AuthorizationModule {
  static forRoot(authServiceProvider: Provider | Type<any>): DynamicModule {
    // Normalize the provider to ensure it has a 'provide' property
    const provider: Provider = this.normalizeProvider(authServiceProvider);

    return {
      module: AuthorizationModule,
      global: true, // Make the module global to avoid importing it in every module
      providers: [
        provider,
        {
          provide: AuthService,
          useExisting: (provider as any).provide || provider, // Map AuthService to the provided class
        },
      ],
      exports: [AuthService], // Export AuthService for use in guards
    };
  }

  private static normalizeProvider(authServiceProvider: Provider | Type<any>): Provider {
    if (typeof authServiceProvider === 'function') {
      return {
        provide: authServiceProvider, // Use the class as the injection token
        useClass: authServiceProvider,
      };
    }
    return authServiceProvider;
  }
}