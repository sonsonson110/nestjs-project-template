import { createZodDto } from 'nestjs-zod';
import { z } from 'zod';

export const forgotPasswordSchema = z.object({
  email: z.string().email('Invalid email format'),
});

export class ForgotPasswordDto extends createZodDto(forgotPasswordSchema) {}
