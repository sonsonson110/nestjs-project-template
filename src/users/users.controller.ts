import { Body, Controller, Post } from '@nestjs/common';
import { ApiOperation, ApiResponse } from '@nestjs/swagger';
import { ApiResponse as IApiResponse } from 'src/common/types/api-response.type';
import { CreateUserDto } from 'src/users/schema/create-user.schema';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  @ApiOperation({
    summary: 'Create a new user',
    description:
      'This endpoint allows you to create a new user with the provided details.',
  })
  @ApiResponse({
    status: 201,
    description: 'Successfully retrieved users',
    schema: {
      type: 'object',
      properties: {
        message: {
          type: 'string',
          example: 'User created successfully',
        },
        data: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              example: '123e4567-e89b-12d3-a456-426614174000',
            },
            username: {
              type: 'string',
              pattern: '^[a-zA-Z0-9_-]{3,50}$',
              description:
                'Username of the user (3-50 characters, alphanumeric and underscores)',
              example: 'user123',
            },
            email: {
              type: 'string',
              format: 'email',
              example: 'user@example.com',
            },
            createdAt: {
              type: 'string',
              format: 'date-time',
              example: '2023-10-01T12:00:00Z',
            },
          },
          required: ['id', 'email', 'username', 'createdAt'],
        },
      },
      required: ['message', 'data'],
      description: 'Response object containing user creation details',
    },
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
