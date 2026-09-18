export async function GET(req: Request, { params }) {
  // ミドルウェアがログイン済みかは見ているが、この注文が自分のものかは見ていない（IDOR）
  return Response.json(await db.from('orders').select('*').eq('id', params.id).single());
}

export async function DELETE(req: Request, { params }) {
  await db.from('orders').delete().eq('id', params.id);
  return new Response(null, { status: 204 });
}
