import { DynamicModule, Provider } from '@nestjs/common';
export declare class AuthModule {
    static forRoot(authServiceProvider: Provider): DynamicModule;
}
