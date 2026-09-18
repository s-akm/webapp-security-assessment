import { Elysia } from 'elysia';

const app = new Elysia()
  .get('/api/admin', ({ user }) => ({ ok: true }), { beforeHandle: requireAuth })
  .post('/api/report', async ({ body }) => {
    await sendMail(body.email);
    return { ok: true };
  })
  .listen(3000);
