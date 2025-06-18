import { Injectable } from '@nestjs/common';
import { TokenPayload } from '../types/token-payload';

@Injectable()
export abstract class AuthService {
  abstract validateToken(token: string): Promise<TokenPayload>;
}