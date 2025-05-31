export const loginRequestBodyOpenApiSchema = {
  type: 'object',
  properties: {
    emailOrUsername: {
      description: 'User email address or username for login',
      oneOf: [
        {
          type: 'string',
          format: 'email',
          description: 'Email address of the user',
          example: 'user@example.com',
        },
        {
          type: 'string',
          pattern: '^[a-zA-Z0-9_-]{3,50}$',
          description:
            'Username of the user (3-50 characters, alphanumeric and underscores)',
          example: 'user123',
        },
      ],
    },
    password: {
      type: 'string',
      minLength: 8,
      maxLength: 100,
      description: 'User password with complexity requirements',
      example: 'Password123!',
    },
    responseType: {
      type: 'string',
      enum: ['cookie', 'json'],
      description: 'Type of response to return',
      example: 'cookie',
    },
  },
  required: ['emailOrUsername', 'password'],
};

export const loginResponseOpenApiSchema = {
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
};
