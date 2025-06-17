export interface TokenPayload {
  sub: string;
  roles: string[];
  iat?: number;
  exp?: number;
}