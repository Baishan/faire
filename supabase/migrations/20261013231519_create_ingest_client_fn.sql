-- Admin-only RPC to issue an ingest client token.
-- Returns the plaintext token once; only its SHA-256 hash is stored.

create or replace function public.create_ingest_client(client_name text)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  new_token text;
begin
  -- Admin check first. "is distinct from" so a null role (no JWT) is rejected too.
  if (auth.jwt() -> 'app_metadata' ->> 'role') is distinct from 'admin' then
    raise exception 'forbidden' using errcode = 'insufficient_privilege';
  end if;

  if client_name is null or length(trim(client_name)) = 0 then
    raise exception 'client_name is required' using errcode = 'invalid_parameter_value';
  end if;

  -- High-entropy token with a recognisable prefix
  new_token := 'faire_ing_' || encode(extensions.gen_random_bytes(32), 'hex');

  -- Store only the hash
  insert into public.ingest_clients (name, token_hash)
  values (trim(client_name), encode(extensions.digest(new_token, 'sha256'), 'hex'));

  return new_token;
end;
$$;

comment on function public.create_ingest_client(text) is
  'Admin-only: creates an ingest client and returns its token (shown once)';

-- Functions are executable by PUBLIC by default, and Supabase also grants anon explicitly
revoke execute on function public.create_ingest_client(text) from public, anon;
grant  execute on function public.create_ingest_client(text) to authenticated;
