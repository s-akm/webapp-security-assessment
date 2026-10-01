import { Body, Controller, Put } from '@nestjs/common'
import { UsersService, UpdateProfileInput } from './users.service'

@Controller('users')
export class UsersController {
  constructor(private readonly users: UsersService, private readonly userId: string) {}

  @Put('me')
  async updateMe(@Body() changes: UpdateProfileInput) {
    return this.users.updateProfile(this.userId, changes)
  }

  @Put('me/name')
  async rename(@Body() changes: UpdateProfileInput) {
    return this.users.updateName(this.userId, changes.displayName)
  }
}
