// Supabase Edge Function。ガードあり
Deno.serve(async (req) => {
  const user = await serverSupabaseUser(req);
  if (!user) return new Response('no', { status: 401 });
  return new Response('{}');
});
