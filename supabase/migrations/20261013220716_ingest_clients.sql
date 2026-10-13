create table  public.ingest_clients(
  id bigint generated always as identity primary key,
  name text not null unique,
  token_hash text not null unique,
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
  last_used_at timestamptz
);

alter table public.ingest_clients enable row level security;

revoke all on public.ingest_clients from anon, authenticated;

alter table public.home_events
  add column client_id bigint
  references public.ingest_clients (id)
  on delete set null;
