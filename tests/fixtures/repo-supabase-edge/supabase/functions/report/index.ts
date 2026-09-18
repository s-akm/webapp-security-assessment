// ガードなし。service_role を使っている
Deno.serve(async (req) => {
  const admin = createClient(Deno.env.get('SUPABASE_URL'), Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'));
  const { email } = await req.json();
  await admin.from('reports').insert({ email });
  return new Response('{}');
});
