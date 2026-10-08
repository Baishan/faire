-- Admins get full access (select/insert/update/delete) via a single "for all" policy

create policy "admins can do anything"
  on public.home_events
  for all
  to authenticated
  using (
    (select auth.jwt()) -> 'app_metadata' ->> 'role' = 'admin'
  )
  with check (
    (select auth.jwt()) -> 'app_metadata' ->> 'role' = 'admin'
  );
