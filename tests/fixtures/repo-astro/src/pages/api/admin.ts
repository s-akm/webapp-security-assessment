export const GET = async ({ locals }) => {
  if (!locals.user) return new Response('no', { status: 401 });
  return new Response('{}');
};
