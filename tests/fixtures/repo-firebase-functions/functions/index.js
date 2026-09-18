const functions = require('firebase-functions');

exports.admin = functions.https.onRequest(async (req, res) => {
  const user = await verifyIdToken(req.headers.authorization);
  if (!user) return res.status(401).send('no');
  res.json({ ok: true });
});

exports.report = functions.https.onRequest(async (req, res) => {
  await sendMail(req.body.email);
  res.json({ ok: true });
});

exports.onWrite = functions.firestore.document('users/{id}').onWrite(async (change) => {
  await db.collection('audit').add({ at: Date.now() });
});
