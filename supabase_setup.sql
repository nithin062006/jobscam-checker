-- Run once in Supabase: SQL Editor -> New query -> paste -> Run
create table if not exists contributions (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  text text not null,
  user_label text not null check (user_label in ('scam','genuine','unsure')),
  tool_level text,
  tool_score int,
  text_hash text not null unique
);
alter table contributions enable row level security;
-- The public (anon) key may only INSERT. Nobody can read rows with it.
drop policy if exists "anon can insert" on contributions;
create policy "anon can insert" on contributions for insert to anon with check (true);
