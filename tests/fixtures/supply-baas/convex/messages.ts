import { query, mutation } from './_generated/server';
export const list = query({ args: {}, handler: async (ctx) => ctx.db.query('messages').collect() });
export const send = mutation({ args: {}, handler: async (ctx) => {} });
