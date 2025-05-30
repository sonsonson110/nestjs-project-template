export const resetPasswordRequestBodyOpenApiSchema = {
  type: 'object',
  properties: {
    resetToken: {
      type: 'string',
      description: "Password reset token sent to the user's email",
      example: 'abc123xyz456',
    },
    newPassword: {
      type: 'string',
      description: 'New password for the user account',
      example: 'NewSecurePassword123!',
    },
  },
  required: ['resetToken', 'newPassword'],
  description: 'Request body for resetting password using a token',
};
