export const resolvers = {
  Query: {
    me: (parent, args, ctx) => { requireAuth(ctx); return ctx.user; },
    users: (parent, args, ctx) => ctx.db.query('select * from users where id = ' + args.id),
  },
  Mutation: {
    sendReport: async (parent, args) => { await sendMail(args.email); return true; },
  },
};
