import { Router } from 'express';
const router = Router();
router.get('/admin/users', async (req, res) => { res.json(await db.user.findMany()); });
router.post('/webhooks/payment', async (req, res) => { res.send('ok'); });
export default router;
