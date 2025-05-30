export const loginRequestBodyOpenApiSchema = {
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
    responseType: {
      type: 'string',
      enum: ['cookie', 'json'],
      description: 'Type of response to return',
      example: 'cookie',
    },
  },
  required: ['email', 'password'],
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
