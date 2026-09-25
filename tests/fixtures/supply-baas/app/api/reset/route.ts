export async function POST(req: Request) {
  const host = req.headers.get('host');
  const link = `https://${host}/reset?token=abc`;
  return Response.json({ link });
}
