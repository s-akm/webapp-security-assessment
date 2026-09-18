// 生 SQL の組み立て
export async function search(term: string) {
  return await db.raw("select id, name from users where name like '%" + term + "%'");
}

// 収集パターンに当たる名前の export。lib/ 配下なので、これがあってもハンドラには数えない。
// （除外の仕組みが効いているかを確かめるための題材）
export const handler = async () => search("");
