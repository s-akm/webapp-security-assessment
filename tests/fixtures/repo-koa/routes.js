const Router = require('@koa/router');
const router = new Router();

router.get('/api/admin', requireAuth, async (ctx) => { ctx.body = { ok: true }; });
router.post('/api/report', async (ctx) => {
  await sendMail(ctx.request.body.email);
  ctx.body = { ok: true };
});
module.exports = router;
