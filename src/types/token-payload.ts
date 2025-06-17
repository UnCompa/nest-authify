export interface TokenPayload {
  sub: string;
  roles?: string[];
  iat?: number;
  exp?: number;
  displayName?: string;
  profile_url?: string;
  twoFactorSecret?: string;
  createdAt?: string;
  updatedAt?: string;
}