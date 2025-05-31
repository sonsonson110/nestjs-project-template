import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { ApiOperation, ApiResponse } from '@nestjs/swagger';
import { Request, Response } from 'express';
import { ForgotPasswordDto } from 'src/auth/schema/forgot-password.schema';
import { LoginDto } from 'src/auth/schema/login.schema';
import { ResetPasswordDto } from 'src/auth/schema/reset-password.schema';
import { SessionInfo } from 'src/auth/types/session-info.type';
import { ApiResponse as IApiResponse } from 'src/common/types/api-response.type';
import { JWTPayload } from 'src/common/types/jwt-payload.type';
import { AuthGuard } from 'src/guards/auth.guard';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  private readonly accessTokenExpiresIn: number = 15 * 60 * 1000;
  private readonly refreshTokenExpiresIn: number = 7 * 24 * 60 * 60 * 1000;
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @ApiOperation({
    summary: 'User login',
    description:
      'This endpoint allows users to log in with their credentials. It supports both cookie and token-based responses.',
  })
  @ApiResponse({
    status: 201,
    description: 'Login successful',
    schema: {
      type: 'object',
      properties: {
        message: {
          type: 'string',
          description: 'Success message',
          example: 'Login successfully',
        },
        data: {
          type: 'object',
          properties: {
            accessToken: {
              type: 'string',
              description: 'JWT access token for authenticated requests',
              example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
            },
            refreshToken: {
              type: 'string',
              description: 'JWT refresh token for renewing access tokens',
              example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
            },
          },
          required: ['accessToken', 'refreshToken'],
        },
      },
      required: ['message'],
      description: 'Response object containing login details',
    },
  })
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<IApiResponse> {
    const sessionInfo: SessionInfo = {
      ipAddress: req.ip || req.socket.remoteAddress,
      userAgent: req.headers['user-agent'],
      deviceInfo: this.extractDeviceInfo(req.headers['user-agent']),
    };
    const result = await this.authService.login(loginDto, sessionInfo);
    if (loginDto.responseType === 'cookie') {
      response.cookie('accessToken', result.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: this.accessTokenExpiresIn,
      });
      response.cookie('refreshToken', result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: this.refreshTokenExpiresIn,
      });
      return { message: 'Login successfully' };
    } else {
      return {
        message: 'Login successfully',
        data: {
          accessToken: result.accessToken,
          refreshToken: result.refreshToken,
        },
      } satisfies IApiResponse;
    }
  }

  private extractDeviceInfo(userAgent?: string): string | undefined {
    if (!userAgent) return undefined;
    if (userAgent.includes('Mobile')) return 'Mobile';
    if (userAgent.includes('Tablet')) return 'Tablet';
    return 'Desktop';
  }

  @UseGuards(AuthGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'User logout',
    description:
      'This endpoint allows users to log out and clear their session.',
  })
  @ApiResponse({
    status: 200,
    description: 'Logout successful',
  })
  async logout(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<IApiResponse> {
    const refreshToken = request.cookies['refreshToken'] as string;
    const { sub } = request['user'] as JWTPayload;
    if (!refreshToken) {
      throw new UnauthorizedException('No refresh token provided');
    }
    await this.authService.logout(sub, refreshToken);
    response.clearCookie('accessToken');
    response.clearCookie('refreshToken');
    return { message: 'Logout successfully' } satisfies IApiResponse;
  }

  @Post('refresh-token')
  @ApiOperation({
    summary: 'Refresh access token',
    description:
      'This endpoint allows users to refresh their access token using a valid refresh token.',
  })
  @ApiResponse({
    status: 201,
    description: 'Access token refreshed successfully',
  })
  async refreshToken(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<IApiResponse> {
    const refreshToken = request.cookies['refreshToken'] as string;
    if (!refreshToken) {
      throw new UnauthorizedException('No refresh token provided');
    }
    const newAccessToken =
      await this.authService.refreshAccessToken(refreshToken);
    response.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: this.accessTokenExpiresIn,
    });
    return {
      message: 'Access token refreshed successfully',
    } satisfies IApiResponse;
  }

  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Forgot password',
    description:
      'This endpoint allows users to request a password reset link by providing their email address.',
  })
  @ApiResponse({
    status: 200,
    description: "Password reset link sent to the user's email",
  })
  async forgotPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto,
  ): Promise<IApiResponse> {
    await this.authService.forgotPasswordAction(forgotPasswordDto.email);
    return {
      message: 'Password reset link sent to your email',
    } satisfies IApiResponse;
  }

  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Reset password',
    description:
      'This endpoint allows users to reset their password using a valid reset token and new password.',
  })
  @ApiResponse({
    status: 200,
    description: 'Password reset successfully',
  })
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
  ): Promise<IApiResponse> {
    await this.authService.resetPassword(resetPasswordDto);
    return { message: 'Password reset successfully' } satisfies IApiResponse;
  }
}
