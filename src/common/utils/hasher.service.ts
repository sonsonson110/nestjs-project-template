import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcryptjs';
import { SHA256 } from 'crypto-js';

@Injectable()
export class HasherService {
  constructor(private readonly configService: ConfigService) {}

  private get saltRounds(): number {
    const rounds = this.configService.get<string>('HASH_SALT_ROUNDS', '12');
    return parseInt(rounds, 10);
  }

  private get hashSecret(): string {
    return this.configService.get<string>('HASH_SECRET')!;
  }

  async hash(input: string, saltRounds?: number): Promise<string> {
    try {
      return await bcrypt.hash(input, saltRounds ?? this.saltRounds);
    } catch (error) {
      throw new InternalServerErrorException(
        `Error hashing input: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }

  async verify(input: string, hashedValue: string): Promise<boolean> {
    try {
      return await bcrypt.compare(input, hashedValue);
    } catch (error) {
      throw new InternalServerErrorException(
        `Error verifying input: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }

  hashDeterministic(input: string): string {
    try {
      const hashInput = input + this.hashSecret;
      const hash = SHA256(hashInput);
      return hash.toString();
    } catch (error) {
      throw new InternalServerErrorException(
        `Error creating deterministic hash: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }

  verifyDeterministic(input: string, hashedValue: string): boolean {
    try {
      return this.hashDeterministic(input) === hashedValue;
    } catch (error) {
      throw new InternalServerErrorException(
        `Error verifying deterministic hash: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }
}
