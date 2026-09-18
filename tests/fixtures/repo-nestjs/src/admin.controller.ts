import { Controller, Get, Post, UseGuards } from '@nestjs/common';

@Controller('admin')
@UseGuards(AuthGuard)
export class AdminController {
  @Get() findAll() { return this.svc.all(); }
}
