export async function POST(req: Request) {
  const { email } = await req.json();
  await sendMail(email);
  return Response.json({ ok: true });
}
