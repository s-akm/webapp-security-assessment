import { router, publicProcedure, protectedProcedure } from './trpc';

export const appRouter = router({
  listUsers: protectedProcedure.query(({ ctx }) => ctx.db.users.findMany()),
  sendReport: publicProcedure.mutation(async ({ input }) => {
    await sendMail(input.email);
    return { ok: true };
  }),
});
