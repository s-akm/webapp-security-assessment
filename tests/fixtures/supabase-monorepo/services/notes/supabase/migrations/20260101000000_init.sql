create table public.accounts (id uuid primary key, name text not null);
create table public.notes (id uuid primary key, account_id uuid references public.accounts (id), body text);
alter table public.notes enable row level security;
