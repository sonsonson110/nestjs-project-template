export interface JWTPayload {
  sub: string;
  email?: string;
  role?: string;
  jti?: string;
  [key: string]: unknown;
}
