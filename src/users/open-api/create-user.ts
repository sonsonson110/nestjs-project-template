export const createUserRequestBodyOpenApiSchema = {
  type: 'object',
  properties: {
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
      description: 'User email address',
      example: 'user@example.com',
    },
    password: {
      type: 'string',
      minLength: 8,
      maxLength: 100,
      description: 'User password with complexity requirements',
      example: 'Password123!',
    },
  },
  required: ['username', 'email', 'password'],
};

export const createUserResponseOpenApiSchema = {
  type: 'object',
  properties: {
    message: {
      type: 'string',
      description: 'Success message',
      example: 'User created successfully',
    },
    data: {
      type: 'object',
      properties: {
        id: {
          type: 'string',
          description: 'Unique identifier for the user',
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
          description: 'Email address of the user',
          example: 'user@example.com',
        },
        createdAt: {
          type: 'string',
          format: 'date-time',
          description: 'Timestamp when the user was created',
          example: '2023-10-01T12:00:00Z',
        },
      },
      required: ['id', 'email', 'username', 'createdAt'],
    },
  },
  required: ['message', 'data'],
  description: 'Response object containing user creation details',
};
