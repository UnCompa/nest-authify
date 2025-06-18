"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var AuthorizationModule_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthorizationModule = void 0;
// libs/auth/src/auth.module.ts
const common_1 = require("@nestjs/common");
const auth_service_1 = require("./services/auth.service");
let AuthorizationModule = AuthorizationModule_1 = class AuthorizationModule {
    static forRoot(authServiceProvider) {
        // Normalize the provider to ensure it has a 'provide' property
        const provider = this.normalizeProvider(authServiceProvider);
        return {
            module: AuthorizationModule_1,
            global: true, // Make the module global to avoid importing it in every module
            providers: [
                provider,
                {
                    provide: auth_service_1.AuthService,
                    useExisting: provider.provide || provider, // Map AuthService to the provided class
                },
            ],
            exports: [auth_service_1.AuthService], // Export AuthService for use in guards
        };
    }
    static normalizeProvider(authServiceProvider) {
        if (typeof authServiceProvider === 'function') {
            return {
                provide: authServiceProvider, // Use the class as the injection token
                useClass: authServiceProvider,
            };
        }
        return authServiceProvider;
    }
};
exports.AuthorizationModule = AuthorizationModule;
exports.AuthorizationModule = AuthorizationModule = AuthorizationModule_1 = __decorate([
    (0, common_1.Module)({})
], AuthorizationModule);
//# sourceMappingURL=auth.module.js.map