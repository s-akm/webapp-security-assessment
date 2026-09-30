create table public.accounts (id uuid primary key, name text not null);
create table public.invoices (id uuid primary key, account_id uuid references public.accounts (id));
alter table public.accounts enable row level security;
alter table public.invoices enable row level security;
