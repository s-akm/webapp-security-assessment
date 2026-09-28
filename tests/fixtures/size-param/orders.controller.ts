@Controller('orders')
export class OrdersController {
  @Get()
  list(@Query('pageSize') pageSize: number) {
    if (pageSize < 1) throw new BadRequestException();
    return this.orders.find({ take: pageSize });
  }
}
