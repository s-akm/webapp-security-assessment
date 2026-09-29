create table memo (id int);
alter table memo enable row level security;
create policy "w" on memo for update using (true) with check (true);
create policy "r" on memo for select to anon using (true);
