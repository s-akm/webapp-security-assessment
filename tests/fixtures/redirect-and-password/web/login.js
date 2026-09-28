// 架空の題材: Express のログイン後の戻り先
const express = require('express');
const app = express();

app.post('/login', async (req, res) => {
  const dest = req.query.next;
  await signIn(req.body);
  res.redirect(dest || '/');
});

app.post('/login-safe', async (req, res) => {
  const back = req.query.returnTo || '/';
  await signIn(req.body);
  if (!back.startsWith('/') || back.startsWith('//')) return res.redirect('/');
  res.redirect(back);
});

app.get('/fetch-preview', async (req, res) => {
  const target = req.query.url;
  const r = await fetch(target);
  res.send(await r.text());
});

app.get('/sso/return', (req, res) => {
  const { continue: _c, redirect_uri } = req.query;
  audit(req);
  res.redirect(redirect_uri);
});

app.get('/logout', (req, res) => {
  const to = req.query.to;
  req.session.destroy();
  if (to && to.startsWith('/')) {
    return res.redirect(to);
  }
  res.redirect('/');
});

app.get('/switch', (req, res) => {
  const r = req.query.redirect;
  res.redirect(getSafeRedirectPath(r, '/'));
});
