export default class ReportController {
  public async store({ request }) {
    await Database.rawQuery('select * from users where id = ' + request.input('id'));
    return { ok: true };
  }
}
