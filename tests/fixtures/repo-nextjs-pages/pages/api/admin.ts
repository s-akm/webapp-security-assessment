// Pages Router。ガードあり
export default async function handler(req, res) {
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).end();
  res.json({ ok: true });
}
