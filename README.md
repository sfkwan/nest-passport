<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="200" alt="Nest Logo" /></a>
</p>

[circleci-image]: https://img.shields.io/circleci/build/github/nestjs/nest/master?token=abc123def456
[circleci-url]: https://circleci.com/gh/nestjs/nest

## Reference

https://docs.nestjs.com/recipes/passport

## Local strategy

### JWT token from local strategy

1. login to generate JWT login and add the token to cookie
   - http://localhost:3000/auth/login

```typescript
@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super();
  }

  async validate(username: string, password: string): Promise<any> {
    const user = await this.authService.validateUser(username, password);
    if (!user) {
      throw new UnauthorizedException();
    }

    return user;
  }
}
```

2. validate local generated jwt token from Cookie/ Authorization: Bearer header
   - http://localhost:3000/auth/profile

```typescript
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      ignoreExpiration: false,
      secretOrKey: jwtConstants.secret,

      jwtFromRequest: ExtractJwt.fromExtractors([
        JwtStrategy.extractJWTFromCookie,
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
    });
  }

```

## Use keycloak to simulate OIDC

### Set up keycloak

1. Use docker compose to start up the keycloak. Realm dev has been created.

1. Follow below to set up user
   - https://medium.com/devops-dudes/secure-front-end-react-js-and-back-end-node-js-express-rest-api-with-keycloak-daf159f0a94e#:~:text=node%2Dmicroservice%20client.-,5.%20Create%20Users,-Users%20are%20entities

### JWT token from OIDC

1. Login using implicit grant flow to get the access token
2. Add to cookie: access_token=xxx
3. Validate keycloak generated jwt token from Cookie/ Authorization: Bearer header
   - http://localhost:3000/auth/profile

```typescript
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      ignoreExpiration: false,
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
```

## Extract JWT from cookie

```typescript
private static extractJWTFromCookie(req: Request): string | null {
  console.log(`Extracting JWT from request: ${JSON.stringify(req.cookies)}`);

  if (req.cookies?.access_token?.length > 0) {
    return req.cookies.access_token;
  }
  return null;
}
```
