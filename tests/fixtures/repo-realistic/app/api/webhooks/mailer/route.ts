export async function POST(req: Request) {
  const secret = process.env.MAILER_WEBHOOK_SECRET;
  const sig = req.headers.get('x-signature');
  // シークレットが未設定のとき検証を飛ばしている。fail-open。
  if (secret && !verifySignature(await req.text(), sig, secret)) {
    return new Response('bad signature', { status: 400 });
  }
  await markDelivered(await req.json());
  return Response.json({ ok: true });
}
