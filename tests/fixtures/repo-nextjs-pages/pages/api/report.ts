// Pages Router。ガードなし
export default async function handler(req, res) {
  await sendMail(req.body.email);
  res.json({ ok: true });
}
