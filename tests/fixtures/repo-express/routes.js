// Express。ミドルウェアを引数で挟む形
const express = require('express');
const app = express();

app.get('/api/admin', requireAuth, (req, res) => res.json({ ok: true }));
app.post('/api/report', (req, res) => {           // ガードなし
  sendMail(req.body.email);
  db.query('select * from users where id = ' + req.query.id);
  res.json({ ok: true });
});
module.exports = app;
