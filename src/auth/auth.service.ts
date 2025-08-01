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
    return this.createTokenPair(payload);
  }

  generateAccessToken(payload: { sub: number; email: string }) {
    return this.jwtService.sign(payload, {
      secret: process.env.JWT_SECRET,
      expiresIn: '15m',
    });
  }

  generateRefreshToken(payload: { sub: number; email: string }) {
    return this.jwtService.sign(payload, {
      secret: process.env.JWT_SECRET,
      expiresIn: '7d',
    });
  }

  createTokenPair(payload: { sub: number; email: string }) {
    return {
      access_token: this.generateAccessToken(payload),
      refresh_token: this.generateRefreshToken(payload),
    };
  }

  async validateRefreshToken(token: string) {
    try {
      return this.jwtService.verify(token, {
        secret: process.env.JWT_SECRET,
      });
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }
}