export class AppService {
  async launch(cmd: string) {
    return spawn(cmd)
  }

  async list() {
    return ['As an assistant, I ran the query and it returned a row']
  }
}
