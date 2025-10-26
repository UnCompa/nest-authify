export enum ProvidersAuth {
  LOCAL = 'local',
  GOOGLE = 'google',
  FACEBOOK = 'facebook',
  GITHUB = 'github',
  TWITTER = 'twitter',
  APPLE = 'apple',
}

export interface AuthSession {
  sub: string;
  roles: string[];
  accessToken: string;
  refreshToken: string;
  provider?: ProvidersAuth;
  providerData?: Record<string, any>;
  sessionId?: string;
}

export interface JwtPayload {
  sub: string;
  roles: string[];
  type: 'access' | 'refresh';
  sessionId?: string;
  iat?: number;
  exp?: number;
}

export interface RefreshTokenPayload {
  sub: string;
  type: 'refresh';
  sessionId?: string;
  iat?: number;
  exp?: number;
}

export interface OAuthProfile {
  id: string;
  displayName?: string;
  name?: {
    familyName?: string;
    givenName?: string;
  };
  emails?: Array<{ value: string; verified?: boolean }>;
  photos?: Array<{ value: string }>;
  provider: string;
}
