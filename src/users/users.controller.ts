import { Body, Controller, Post, UsePipes } from '@nestjs/common';
import { ApiBody, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { ZodValidationPipe } from 'src/common/pipes/zod-validation.pipe';
import { ApiResponse as IApiResponse } from 'src/common/types/api-response.type';
import {
  createUserRequestBodyOpenApiSchema,
  createUserResponseOpenApiSchema,
} from 'src/users/open-api/create-user';
import {
  CreateUserDto,
  createUserSchema,
} from 'src/users/schema/create-user.schema';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  @UsePipes(new ZodValidationPipe(createUserSchema))
  @ApiOperation({
    summary: 'Create a new user',
    description:
      'This endpoint allows you to create a new user with the provided details.',
  })
  @ApiBody({ schema: createUserRequestBodyOpenApiSchema })
  @ApiResponse({
    status: 201,
    description: 'Successfully retrieved users',
    schema: createUserResponseOpenApiSchema,
  })
  async create(@Body() createUserDto: CreateUserDto): Promise<IApiResponse> {
    const result = await this.usersService.createUser(createUserDto);
    return {
      message: 'User created successfully',
      data: {
        id: result.id,
        email: result.email,
        createdAt: result.createdAt,
      },
    } satisfies IApiResponse;
  }
}
