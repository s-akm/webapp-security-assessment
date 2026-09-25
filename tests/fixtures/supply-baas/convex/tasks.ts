import { query } from './_generated/server';
export const mine = query({ args: {}, handler: async (ctx) => {
  const identity = await ctx.auth.getUserIdentity();
  if (!identity) throw new Error('unauthorized');
  return [];
}});
export const all = query({ args: {}, handler: async (ctx) => ctx.db.query('tasks').collect() });
