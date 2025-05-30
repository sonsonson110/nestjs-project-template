export const createUserRequestBodyOpenApiSchema = {
  type: 'object',
  properties: {
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
  required: ['email', 'password'],
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
      required: ['id', 'email', 'createdAt'],
    },
  },
  required: ['message', 'data'],
  description: 'Response object containing user creation details',
};
