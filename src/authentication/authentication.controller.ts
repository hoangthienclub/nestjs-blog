import { Body, Controller, HttpCode, Post, Req, Res, UseGuards, Get } from "@nestjs/common";
import { Response } from 'express';
import AuthenticationService from "./authentication.service";
import RegisterDto from "./dto/register.dto";
import JwtAuthenticationGuard from "./jwt-authentication.guard";
import { LocalAuthenticationGuard } from "./localAuthentication.guard";
import RequestWithUser from './requestWithUser.interface';

@Controller('authentication')
export class Authentication {
  constructor(
    private readonly authenticationService: AuthenticationService
  ) {}

  @Post('register')
  async register(@Body() registrationData: RegisterDto) {
    return this.authenticationService.register(registrationData);
  }

  @HttpCode(200)
  @UseGuards(LocalAuthenticationGuard)
  @Post('log-in')
  async logIn(@Req() request: RequestWithUser, @Res() response: Response) {
    console.log('thien')
    const { user } = request;
    const cookie = this.authenticationService.getCookieWithJwtToken(user.id);
    response.setHeader('Set-Cookie', cookie);
    user.password = undefined;
    return response.send(user);
  }

  @UseGuards(JwtAuthenticationGuard)
  @Post('log-out')
  async logOut(@Req() request: RequestWithUser, @Res() response: Response) {
    response.setHeader('Set-Cookie', this.authenticationService.getCookieForLogOut());
    return response.sendStatus(200);
  }

  @UseGuards(JwtAuthenticationGuard)
  @Get()
  authenticate(@Req() request: RequestWithUser) {
    const user = request.user;
    user.password = undefined;
    return user;
  }

}

export default Authentication;