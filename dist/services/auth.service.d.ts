import { TokenPayload } from '../types/token-payload';
export declare abstract class AuthService {
    abstract validateToken(token: string): Promise<TokenPayload>;
}
//# sourceMappingURL=auth.service.d.ts.map