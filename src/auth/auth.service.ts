import { Injectable } from '@nestjs/common';
import { IUser, UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';

export type UserWithoutPassword = Omit<IUser, 'password'>;
export interface IJwtPayload {
  username: string;
  sub: number;
  given_name?: string;
}

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async validateUser(
    username: string,
    pass: string,
  ): Promise<UserWithoutPassword | null> {
    const user = await this.usersService.findOne(username);
    if (user && user.password === pass) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async login(user: UserWithoutPassword) {
    const payload: IJwtPayload = { username: user.username, sub: user.userId };
    return {
      access_token: this.jwtService.sign(payload, {
        issuer: 'prkwan',
        audience: 'nest-passport',
      }),
    };
  }
}
