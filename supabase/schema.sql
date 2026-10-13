-- Run this once in Supabase: SQL Editor -> New query -> paste -> Run.

create table public.passwords (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null default auth.uid() references auth.users(id) on delete cascade,
  website_enc  text not null,   -- every *_enc column holds base64(nonce + Loom ciphertext + MAC tag)
  username_enc text not null,
  password_enc text not null,
  notes_enc    text,
  created_at   timestamptz not null default now()
);

create index passwords_user_id_idx on public.passwords (user_id);

-- Row Level Security: each user can only touch their own rows.
alter table public.passwords enable row level security;

create policy "read own passwords"   on public.passwords for select using (auth.uid() = user_id);
create policy "insert own passwords" on public.passwords for insert with check (auth.uid() = user_id);
create policy "update own passwords" on public.passwords for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "delete own passwords" on public.passwords for delete using (auth.uid() = user_id);

-- Enforce the 100 password cap in the database so it can't be bypassed from the browser.
create or replace function public.enforce_password_limit()
returns trigger language plpgsql as $$
begin
  if (select count(*) from public.passwords where user_id = new.user_id) >= 100 then
    raise exception 'Password limit of 100 reached';
  end if;
  return new;
end;
$$;

create trigger passwords_limit
  before insert on public.passwords
  for each row execute function public.enforce_password_limit();
