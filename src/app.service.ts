import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AppService {
  constructor(private configService: ConfigService) {
    console.log('JWT Secret:', this.configService.get<string>('jwt.secret'));
    console.log(
      'Database Connection String:',
      this.configService.get<string>('database.connectionString'),
    );
  }
  getHello(): string {
    return 'Hello World!';
  }
}
