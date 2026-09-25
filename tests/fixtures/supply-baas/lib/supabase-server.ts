import { createServerClient } from '@supabase/ssr';
export async function requireAdmin() {
  const supabase = createServerClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!, { cookies: {} as any });
  const { data } = await supabase.auth.getSession();
  return data.session?.user;
}
