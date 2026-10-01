import { createClient } from '@supabase/supabase-js'

const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!)

export function listen(room: string, onMessage: (m: unknown) => void) {
  return supabase.channel(`room:${room}`).on('broadcast', { event: 'message' }, onMessage).subscribe()
}
