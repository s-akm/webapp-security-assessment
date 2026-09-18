export async function PATCH(req: Request, { params }) {
  const user = await getCurrentUser(req);
  if (!isAdmin(user)) return new Response('no', { status: 403 });
  const body = await req.json();
  // 受け取ったオブジェクトをそのまま渡している（マスアサインメント）
  await db.from('members').update(body).eq('id', params.memberId);
  return Response.json({ ok: true });
}
