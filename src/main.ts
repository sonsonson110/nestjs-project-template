import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import * as cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { ConsoleLogger } from '@nestjs/common';
import { patchNestJsSwagger } from 'nestjs-zod';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: new ConsoleLogger({
      colors: process.env.NODE_ENV !== 'production',
    }),
  });
  app.use(helmet());
  app.use(cookieParser());

  if (process.env.NODE_ENV !== 'production') {
    patchNestJsSwagger();

    const config = new DocumentBuilder()
      .setTitle('NestJS template')
      .setDescription('NestJS template API description')
      .setVersion('1.0')
      .build();
    const documentFactory = () => SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('swagger', app, documentFactory);
  }

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
