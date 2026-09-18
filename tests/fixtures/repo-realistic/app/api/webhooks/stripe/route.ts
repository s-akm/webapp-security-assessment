export async function POST(req: Request) {
  const sig = req.headers.get('stripe-signature');
  const raw = await req.text();
  const event = stripe.webhooks.constructEvent(raw, sig, process.env.STRIPE_WEBHOOK_SECRET);
  if (event.type === 'checkout.session.completed') await grantAccess(event.data.object);
  return Response.json({ received: true });
}
