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

create table public.room_members (
  room_id uuid not null references public.rooms (id),
  user_id uuid not null references auth.users (id),
  role    text not null default 'member'
);

create table public.profiles (
  id           uuid primary key references auth.users (id),
  display_name text,
  is_admin     boolean not null default false
);

create table public.settings (
  id    uuid primary key references auth.users (id),
  theme text,
  plan  text not null default 'free'
);

alter table public.room_members enable row level security;
alter table public.profiles enable row level security;
alter table public.settings enable row level security;

create policy "Profiles: update own"
  on public.profiles for update
  using (auth.uid() = id);

create policy "Settings: update own"
  on public.settings for update
  using (auth.uid() = id);

revoke update on public.settings from authenticated;
grant update (theme) on public.settings to authenticated;

create policy "Room members read messages"
  on public.messages for select
  using (exists (select 1 from public.room_members m where m.room_id = room_id and m.user_id = auth.uid()));

create policy "Room members read rooms"
  on public.rooms for select
  using (exists (select 1 from public.room_members m where m.room_id = rooms.id and m.user_id = auth.uid()));
