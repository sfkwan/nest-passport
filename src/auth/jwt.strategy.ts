import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { jwtConstants } from './constant';
import { IJwtPayload } from './auth.service';
import { passportJwtSecret } from 'jwks-rsa';

import { Request } from 'express';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      ignoreExpiration: false,
      //secretOrKey: jwtConstants.secret,

      secretOrKeyProvider: passportJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `http://localhost:8080/realms/dev/protocol/openid-connect/certs`,
      }),
      audience: `account`,
      issuer: `http://localhost:8080/realms/dev`,
      algorithms: ['RS256'],

      jwtFromRequest: ExtractJwt.fromExtractors([
        JwtStrategy.extractJWTFromCookie,
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
    });
  }

  private static extractJWTFromCookie(req: Request): string | null {
    console.log(`Extracting JWT from request: ${JSON.stringify(req.cookies)}`);

    if (req.cookies?.access_token?.length > 0) {
      return req.cookies.access_token;
    }
    return null;
  }

  async validate(payload: IJwtPayload) {
    return {
      ...payload,
    };
  }
}
