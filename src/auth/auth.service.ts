import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  private hash(password: string) {
    return crypto.createHash('sha256').update(password).digest('hex');
  }

  async register(email: string, password: string) {
    const hashed = this.hash(password);
    return this.usersService.create(email, hashed);
  }

  async validate(email: string, password: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user || user.password !== this.hash(password)) {
      throw new UnauthorizedException('Неверные учетные данные');
    }
    return user;
  }

  async login(user: any) {
    const payload = { sub: user.id, email: user.email };
    const access = this.jwtService.sign(payload, { expiresIn: '15m' });
    const refresh = this.jwtService.sign(payload, {
      secret: process.env.JWT_REFRESH_SECRET,
      expiresIn: '7d',
    });
    return { access_token: access, refresh_token: refresh };
  }
}