import { ConflictException, Injectable } from '@nestjs/common';
import { HasherService } from 'src/common/utils/hasher.service';
import { PrismaService } from 'src/common/libs/prisma/prisma.service';
import { CreateUserDto } from 'src/users/schema/create-user.schema';
import { User } from '@prisma/client';

@Injectable()
export class UsersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly hasherService: HasherService,
  ) {}

  async createUser(dto: CreateUserDto): Promise<User> {
    const emailExists = await this.prisma.user.findFirst({
      where: { email: dto.email },
      select: { id: true },
    });
    if (emailExists) {
      throw new ConflictException('User with this email already exists');
    }
    const usernameExists = await this.prisma.user.findFirst({
      where: { username: dto.username },
      select: { id: true },
    });
    if (usernameExists) {
      throw new ConflictException('User with this username already exists');
    }
    const hashedPassword = await this.hasherService.hash(dto.password);
    return this.prisma.user.create({
      data: {
        username: dto.username,
        email: dto.email,
        passwordHash: hashedPassword,
      },
    });
  }

  async findAllUsers() {}
}
