import { Hono } from 'hono';
const app = new Hono();

app.get('/api/admin', requireAuth, (c) => c.json({ ok: true }));
app.post('/api/report', async (c) => {
  const body = await c.req.json();
  await db.query('select * from users where id = ' + body.id);
  return c.json({ ok: true });
});
export default app;
