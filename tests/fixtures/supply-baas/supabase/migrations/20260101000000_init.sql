create table public.orders (id uuid primary key, user_id uuid not null);
alter table public.orders enable row level security;

create table profiles (id uuid primary key, role text);

create table private.audit_log (id bigint primary key);

create or replace function public.admin_list_profiles()
returns setof profiles
language sql
security definer
as $$ select * from profiles $$;

create or replace function public.my_orders()
returns setof public.orders
language sql
security definer
set search_path = ''
as $$ select * from public.orders where user_id = auth.uid() $$;

create view public.order_summary as select user_id, count(*) from public.orders group by user_id;
create view public.my_order_view with (security_invoker = true) as select * from public.orders;
create materialized view public.order_stats as select count(*) from public.orders;

create policy "admins read" on public.orders for select
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');

insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);

alter publication supabase_realtime add table profiles;
alter table profiles replica identity full;
