import { createZodDto } from 'nestjs-zod';
import { z } from 'zod';

export const loginSchema = z.object({
  emailOrUsername: z
    .string()
    .min(1, { message: 'Email or username is required' })
    .refine(
      (value) => {
        // Check if it's a valid email or a valid username
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const usernameRegex = /^[a-zA-Z0-9_-]{3,50}$/;

        return emailRegex.test(value) || usernameRegex.test(value);
      },
      {
        message: 'Must be a valid email address or username',
      },
    ),
  password: z
    .string()
    .min(8, { message: 'Password must be at least 8 characters long' })
    .max(100, { message: 'Password must not exceed 100 characters' })
    .refine((password) => /[A-Z]/.test(password), {
      message: 'Password must contain at least one uppercase letter',
    })
    .refine((password) => /[a-z]/.test(password), {
      message: 'Password must contain at least one lowercase letter',
    })
    .refine((password) => /[0-9]/.test(password), {
      message: 'Password must contain at least one number',
    })
    .refine((password) => /[^A-Za-z0-9]/.test(password), {
      message: 'Password must contain at least one special character',
    }),
  responseType: z.enum(['json', 'cookie']).optional().default('cookie'),
});

export class LoginDto extends createZodDto(loginSchema) {}
