import { query } from './_generated/server'

export const list = query({
  handler: async (ctx) => {
    return await ctx.db.query('messages').collect()
  },
})

export const mine = query({
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity()
    if (!identity) throw new Error('unauthorized')
    return await ctx.db.query('messages').filter((q) => q.eq(q.field('owner'), identity.subject)).collect()
  },
})
