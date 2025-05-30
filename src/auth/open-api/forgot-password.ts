export const forgotPasswordRequestBodyOpenApiSchema = {
  type: 'object',
  properties: {
    email: {
      type: 'string',
      format: 'email',
      description: 'Email address of the user requesting password reset',
      example: 'user@example.com',
    },
  },
  required: ['email'],
  description: 'Request body for forgot password action',
};
