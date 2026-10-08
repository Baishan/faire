-- Roles come from auth.users.raw_app_meta_data -> JWT app_metadata.role

create policy "readers can view events"
  on public.home_events
  for select
  to authenticated
  using (
    (select auth.jwt()) -> 'app_metadata' ->> 'role' = 'reader'
  );

create policy "writers can insert events"
  on public.home_events
  for insert
  to authenticated
  with check (
    (select auth.jwt()) -> 'app_metadata' ->> 'role' = 'writer'
  );
