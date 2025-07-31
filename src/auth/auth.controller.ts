import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { plainToInstance } from 'class-transformer';
import { validateOrReject } from 'class-validator';
import { UseGuards, Get, Request } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  async register(@Body() body: RegisterDto) {
    const dto = plainToInstance(RegisterDto, body);
    await validateOrReject(dto);
    const user = await this.authService.register(dto.email, dto.password);
    return { id: user.id, email: user.email };
  }

  @Post('login')
  async login(@Body() body: LoginDto) {
    const dto = plainToInstance(LoginDto, body);
    await validateOrReject(dto);
    const user = await this.authService.validate(dto.email, dto.password);
    return this.authService.login(user);
  }

  @Post('refresh')
  async refresh(@Body('refresh_token') token: string) {
    const payload = await this.authService['jwtService'].verify(token, {
      secret: process.env.JWT_REFRESH_SECRET,
    });
    const access = this.authService['jwtService'].sign({
      sub: payload.sub,
      email: payload.email,
    });
    return { access_token: access };
  }
  
  @Get('me')
  @UseGuards(JwtAuthGuard)
  getMe(@Request() req) {
    return req.user;
  }

}