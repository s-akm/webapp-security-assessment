import { supabase } from './browser';
export function joinRoom(id: string) {
  return supabase.channel('room:' + id)
    .on('broadcast', { event: 'msg' }, () => {})
    .subscribe();
}
export function myInbox(uid: string) {
  return supabase.channel(`user:${uid}`, {
    config: { private: true },
  }).subscribe();
}
export function watchOrders() {
  return supabase.channel('orders-feed')
    .on('postgres_changes', { event: '*', schema: 'public', table: 'orders' }, () => {})
    .subscribe();
}
