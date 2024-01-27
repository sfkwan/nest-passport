import { Controller, Post, UseGuards, Req, Get, Res } from '@nestjs/common';

import { Request, Response } from 'express';
import { LocalAuthGuard } from './local-auth.guard';
import { AuthService } from './auth.service';
import { IUser } from '../users/users.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { Public } from './meta/public.meta';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  @Public()
  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    console.log(`Login request: ${JSON.stringify(req.user)}`);
    const token = await this.authService.login(req.user as IUser);

    res.cookie('access_token', token.access_token, {
      httpOnly: true,
      secure: true,
    });
    return token;
  }
  @UseGuards(JwtAuthGuard)
  @Get('profile')
  async profile(@Req() req: Request) {
    console.log(`Profile request: ${JSON.stringify(req.user)}`);

    return req.user;
  }

  @Public()
  @Get('public')
  async public() {
    return `this is a public function`;
  }
}
