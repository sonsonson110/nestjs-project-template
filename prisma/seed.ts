/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { PrismaClient, Role } from '@prisma/client';
import * as bcrypt from 'bcryptjs';

// initialize Prisma Client
const prisma = new PrismaClient();

async function main() {
  const adminEmail = process.env.ADMIN_EMAIL!;
  const adminPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD!, 12);
  const adminUsername = process.env.ADMIN_USERNAME!;
  if (!adminEmail || !adminPassword || !adminUsername) {
    throw new Error(
      'ADMIN_EMAIL, ADMIN_USERNAME and ADMIN_PASSWORD environment variables must be set',
    );
  }
  const adminUser = await prisma.user.upsert({
    where: { email: adminEmail },
    update: {},
    create: {
      username: adminUsername,
      email: adminEmail,
      passwordHash: adminPassword,
      role: Role.ADMIN,
    },
  });
  console.log(`Admin user created: ${adminUser.createdAt.toISOString()}`);
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });
