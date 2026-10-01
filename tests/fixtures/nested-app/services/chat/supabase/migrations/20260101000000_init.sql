create table public.rooms (
  id   uuid primary key default gen_random_uuid(),
  name text not null
);

create table public.messages (
  id      uuid primary key default gen_random_uuid(),
  room_id uuid not null references public.rooms (id),
  user_id uuid not null references auth.users (id),
  body    text not null
);

alter table public.rooms enable row level security;
alter table public.messages enable row level security;

create policy "Rooms are visible to signed-in users"
  on public.rooms for select
  using (auth.role() = 'authenticated');

create policy "Messages are visible to signed-in users"
  on public.messages for select
  using (auth.role() = 'authenticated');

create policy "Users post their own messages"
  on public.messages for insert
  with check (auth.uid() = user_id);
