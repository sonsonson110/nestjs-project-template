import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import {
  BadRequestException,
  Inject,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { LoginDto } from 'src/auth/schema/login.schema';
import { SessionInfo } from 'src/auth/types/session-info.type';
import { PrismaService } from 'src/common/libs/prisma/prisma.service';
import { JWTPayload } from 'src/common/types/jwt-payload.type';
import { HasherService } from 'src/common/utils/hasher.service';
import { v4 as uuidv4 } from 'uuid';
import { ResetPasswordDto } from 'src/auth/schema/reset-password.schema';

@Injectable()
export class AuthService {
  private readonly resetTokenPrefix = 'reset_token:';
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly jwtService: JwtService,
    private readonly prismaService: PrismaService,
    private readonly hasher: HasherService,
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
  ) {}
  async login(
    dto: LoginDto,
    sessionInfo: SessionInfo,
  ): Promise<{
    accessToken: string;
    refreshToken?: string;
  }> {
    const user = await this.prismaService.user.findFirst({
      where: {
        OR: [{ email: dto.emailOrUsername }, { username: dto.emailOrUsername }],
      },
      select: {
        id: true,
        username: true,
        email: true,
        passwordHash: true,
      },
    });

    if (!user) {
      throw new BadRequestException('User is not exist');
    }

    const passwordMatch = await this.hasher.verify(
      dto.password,
      user.passwordHash,
    );
    if (!passwordMatch) {
      throw new BadRequestException('Invalid password');
    }

    const accessPayload = {
      sub: user.id,
      username: user.username,
      email: user.email,
    } satisfies JWTPayload;

    const accessToken = await this.jwtService.signAsync(accessPayload);

    const tokenId = uuidv4(); // Generate a unique token ID
    const refreshPayload = {
      ...accessPayload,
      jti: tokenId,
    } satisfies JWTPayload;
    const refreshToken = await this.jwtService.signAsync(refreshPayload, {
      expiresIn: '7d',
    });
    // Save the hashed token in the session table
    const hashedRefreshToken = await this.hasher.hash(refreshToken);
    await this.prismaService.refreshToken.create({
      data: {
        tokenId: tokenId,
        token: hashedRefreshToken,
        userId: user.id,
        deviceInfo: sessionInfo.deviceInfo,
        ipAddress: sessionInfo.ipAddress,
        userAgent: sessionInfo.userAgent,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });
    return {
      accessToken,
      refreshToken,
    };
  }

  async logout(userId: string, refreshToken: string) {
    const { jti }: { jti: string } =
      await this.jwtService.verifyAsync(refreshToken);
    if (!jti) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    const sessionRefreshToken =
      await this.prismaService.refreshToken.findUnique({
        where: { tokenId: jti, userId },
        select: { id: true, token: true },
      });
    if (!sessionRefreshToken) {
      throw new UnauthorizedException('Session not found');
    }
    // Check for token validity with hashed one
    const isStoredTokenValid = await this.hasher.verify(
      refreshToken,
      sessionRefreshToken.token,
    );
    if (!isStoredTokenValid) {
      throw new UnauthorizedException('Invalid session');
    }
    // Update the session to mark it as logged out
    await this.prismaService.refreshToken.update({
      where: { id: sessionRefreshToken.id },
      data: { isRevoked: true, revokedAt: new Date() },
    });
  }

  async refreshAccessToken(refreshToken: string): Promise<string> {
    const { jti, sub }: JWTPayload =
      await this.jwtService.verifyAsync(refreshToken);
    if (!jti || !sub) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    const sessionRefreshToken =
      await this.prismaService.refreshToken.findUnique({
        where: { tokenId: jti, userId: sub, isRevoked: false },
        select: { id: true, token: true },
      });
    if (!sessionRefreshToken) {
      throw new UnauthorizedException('Session not found or revoked');
    }
    // Check for token validity with hashed one
    const isStoredTokenValid = await this.hasher.verify(
      refreshToken,
      sessionRefreshToken.token,
    );
    if (!isStoredTokenValid) {
      throw new UnauthorizedException('Invalid session');
    }
    const accessPayload = { sub } satisfies JWTPayload;
    const newAccessToken = await this.jwtService.signAsync(accessPayload);
    // Update the session with last used timestamp
    await this.prismaService.refreshToken.update({
      where: { id: sessionRefreshToken.id },
      data: { lastUsedAt: new Date() },
    });
    return newAccessToken;
  }

  async forgotPasswordAction(email: string): Promise<void> {
    const user = await this.prismaService.user.findUnique({
      where: { email },
      select: { id: true, email: true },
    });
    if (!user) {
      throw new BadRequestException('Email is not exist');
    }
    const resetToken = uuidv4();
    const hashedResetToken = this.hasher.hashDeterministic(resetToken);

    const cacheKey = this.resetTokenPrefix + hashedResetToken;
    const tokenData = {
      userId: user.id,
      createdAt: new Date().toISOString(),
    };
    const expiresIn = 15 * 60 * 1000; // 15 minutes
    await this.cacheManager.set(cacheKey, JSON.stringify(tokenData), expiresIn);

    this.logger.log(`Reset token for ${email} is ${resetToken}`);
  }

  async resetPassword(dto: ResetPasswordDto): Promise<void> {
    const hashedResetToken = this.hasher.hashDeterministic(dto.resetToken);
    const cacheKey = this.resetTokenPrefix + hashedResetToken;
    const tokenDataString = await this.cacheManager.get<string>(cacheKey);
    if (!tokenDataString) {
      throw new BadRequestException('Invalid or expired reset token');
    }
    const tokenData = JSON.parse(tokenDataString) as {
      userId: string;
      createdAt: string;
    };
    const newHashedPassword = await this.hasher.hash(dto.newPassword);
    await this.prismaService.user.update({
      where: { id: tokenData.userId },
      data: { passwordHash: newHashedPassword },
    });
    // Clear the cache entry after successful password reset
    await this.cacheManager.del(cacheKey);
  }
}
