import { TokenPayload } from '../types/token-payload';
export declare abstract class AuthService {
    abstract validateToken(token: string): Promise<TokenPayload>;
}
