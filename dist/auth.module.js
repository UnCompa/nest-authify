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
        // Handle both Provider and Type<any>
        const provider = this.normalizeProvider(authServiceProvider);
        return {
            module: AuthorizationModule_1,
            providers: [provider, { provide: auth_service_1.AuthService, useExisting: provider.provide || provider }],
            exports: [auth_service_1.AuthService],
        };
    }
    static normalizeProvider(authServiceProvider) {
        // If it's a class (Type<any>), convert it to a ClassProvider
        if (typeof authServiceProvider === 'function') {
            return {
                provide: auth_service_1.AuthService,
                useClass: authServiceProvider,
            };
        }
        // Otherwise, assume it's a valid Provider (e.g., ClassProvider)
        return authServiceProvider;
    }
};
exports.AuthorizationModule = AuthorizationModule;
exports.AuthorizationModule = AuthorizationModule = AuthorizationModule_1 = __decorate([
    (0, common_1.Module)({})
], AuthorizationModule);
//# sourceMappingURL=auth.module.js.map