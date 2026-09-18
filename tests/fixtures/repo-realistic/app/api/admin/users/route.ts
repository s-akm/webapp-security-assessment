export async function GET(req: Request) {
  const user = await getCurrentUser(req);
  if (!isAdmin(user)) return new Response('no', { status: 403 });
  return Response.json(await db.from('users').select('id'));
}
