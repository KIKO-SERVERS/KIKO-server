import {
  Body,
  Controller,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from './jwt-auth.guard';
import { Public } from 'src/common/decorators/public.decorator';

@UseGuards(JwtAuthGuard)
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('register')
  async register(@Body() dto: RegisterDto) {
    const user = await this.authService.register(dto.email, dto.password);
    return { id: user.id, email: user.email };
  }

  @Public()
  @Post('login')
  async login(@Body() dto: LoginDto) {
    const user = await this.authService.validate(dto.email, dto.password);
    return this.authService.login(user);
  }

  @Public()
  @Post('refresh')
  async refresh(@Body('refresh_token') token: string) {
    const payload = await this.authService.validateRefreshToken(token);
    const access_token = this.authService.generateAccessToken({
      sub: payload.sub,
      email: payload.email,
    });
    return { access_token };
  }
}