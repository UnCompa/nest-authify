"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ROLES_KEY = exports.IS_PUBLIC_KEY = void 0;
exports.Auth = Auth;
const common_1 = require("@nestjs/common");
const jwt_auth_guard_1 = require("../guards/jwt-auth.guard");
exports.IS_PUBLIC_KEY = 'isPublic';
exports.ROLES_KEY = 'roles';
function Auth(options = {}) {
    const { isPublic = false, roles = [] } = options;
    return (0, common_1.applyDecorators)((0, common_1.SetMetadata)(exports.IS_PUBLIC_KEY, isPublic), (0, common_1.SetMetadata)(exports.ROLES_KEY, roles), (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard));
}
//# sourceMappingURL=auth.decorator.js.map