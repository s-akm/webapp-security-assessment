@Controller('/api')
export class AppController {
  @Get('list')
  list() {
    return this.service.all()
  }

  @Get('run')
  run(@Query('cmd') cmd: string) {
    return exec(cmd)
  }
}
