@Controller('/api/items')
export class ItemsController {
  @Get()
  @UseGuards(AuthGuard)
  list() {}

  @UseGuards(AuthGuard)
  @ApiOperation({
    summary: 'update',
  })
  @Put(':id')
  update() {}

  @Delete(':id')
  remove() {}

  @Get('/metrics')
  metrics() {}
}
