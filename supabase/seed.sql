-- Local test data. Runs after migrations on `supabase db reset`.
-- NEVER run against production: these users have a shared, known password.

-- ---------------------------------------------------------------------------
-- Test users for the RLS lab (password for all: password123)
-- ---------------------------------------------------------------------------
-- Creating auth users in SQL needs rows in BOTH auth.users and auth.identities,
-- otherwise password login fails. Token columns must be '' (not null) or
-- GoTrue errors when it reads the row.

with seed_users (id, email, role) as (
  values
    ('00000000-0000-0000-0000-000000000001'::uuid, 'admin@test.local',   'admin'),
    ('00000000-0000-0000-0000-000000000002'::uuid, 'readers@test.local', 'reader'),
    ('00000000-0000-0000-0000-000000000003'::uuid, 'writers@test.local', 'writer')
),
inserted_users as (
  insert into auth.users (
    instance_id,
    id,
    aud,
    role,
    email,
    encrypted_password,
    email_confirmed_at,
    raw_app_meta_data,
    raw_user_meta_data,
    created_at,
    updated_at,
    confirmation_token,
    recovery_token,
    email_change_token_new,
    email_change
  )
  select
    '00000000-0000-0000-0000-000000000000',
    id,
    'authenticated',
    'authenticated',
    email,
    extensions.crypt('password123', extensions.gen_salt('bf')),
    now(),
    jsonb_build_object('provider', 'email', 'providers', jsonb_build_array('email'), 'role', role),
    '{}'::jsonb,
    now(),
    now(),
    '',
    '',
    '',
    ''
  from seed_users
  returning id, email
)
insert into auth.identities (
  id,
  user_id,
  provider_id,
  identity_data,
  provider,
  last_sign_in_at,
  created_at,
  updated_at
)
select
  gen_random_uuid(),
  id,
  id::text,
  jsonb_build_object('sub', id::text, 'email', email, 'email_verified', true),
  'email',
  now(),
  now(),
  now()
from inserted_users;
