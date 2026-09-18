// Webhook の受け口。署名検証をしていない（audit_grep の 11 節で検出されるべき）。
export async function POST(req: Request) {
  const event = await req.json();
  if (event.type === 'payment.succeeded') await grantCredit(event.data.userId);
  return Response.json({ received: true });
}
