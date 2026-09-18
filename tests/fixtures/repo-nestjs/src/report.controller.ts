import { Controller, Post, Body } from '@nestjs/common';

@Controller('report')
export class ReportController {
  @Post()
  async create(@Body() body) {
    await this.db.query('select * from users where id = ' + body.id);
    return { ok: true };
  }
}
