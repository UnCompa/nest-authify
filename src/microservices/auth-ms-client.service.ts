import { Inject, Injectable } from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { firstValueFrom } from 'rxjs';

@Injectable()
export class AuthMsClientService {
  constructor(
    @Inject('AUTH_MICROSERVICE') private client: ClientProxy,
  ) { }

  async validateToken(token: string): Promise<any> {
    return firstValueFrom(
      this.client.send({ cmd: 'validate_token' }, { token })
    );
  }

  async getUserById(userId: string): Promise<any> {
    return firstValueFrom(
      this.client.send({ cmd: 'get_user' }, { userId })
    );
  }

  async login(username: string, password: string): Promise<any> {
    return firstValueFrom(
      this.client.send({ cmd: 'login' }, { username, password })
    );
  }

  async refreshToken(refreshToken: string): Promise<any> {
    return firstValueFrom(
      this.client.send({ cmd: 'refresh_token' }, { refreshToken })
    );
  }
}