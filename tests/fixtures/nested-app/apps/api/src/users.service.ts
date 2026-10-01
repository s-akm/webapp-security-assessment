export class UpdateProfileInput {
  displayName?: string
  bio?: string
}

export class UsersService {
  constructor(private readonly repo: { update(id: string, values: object): Promise<void> }) {}

  async updateProfile(id: string, input: UpdateProfileInput) {
    return this.repo.update(id, { ...input })
  }

  async updateName(id: string, displayName?: string) {
    return this.repo.update(id, { displayName })
  }
}
