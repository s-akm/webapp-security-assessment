'use client';
import { supabase } from './browser';
export function Header() {
  supabase.auth.getSession().then(() => {});
  return null;
}
