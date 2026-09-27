@Controller('/api/photos')
export class PhotosController {
  @Delete(':id')
  remove(@Param('id') id: string, @Query('isAdmin') isAdmin: string) {
    return this.service.remove(id, isAdmin === 'true')
  }

  @Get()
  list(@Query('page') page: string) {
    return this.service.list(page)
  }

  @Put('/me')
  updateMe(@Body() body: UserDto) {
    return this.users.update(this.userId, body)
  }
}
