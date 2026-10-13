-- Track who inserted each row so writers can read back their own events.
-- Nullable: rows inserted with the service key have no auth.uid().
-- on delete set null: keep event history if a user is deleted.

alter table public.home_events
  add column created_by uuid
    default auth.uid()
    references auth.users (id)
    on delete set null;

-- Supports the writer select policy (created_by = current user)
create index home_events_created_by_idx
  on public.home_events (created_by);

create policy "writers can view own events"
  on public.home_events
  for select
  to authenticated
  using (
    (select auth.jwt()) -> 'app_metadata' ->> 'role' = 'writer'
    and created_by = (select auth.uid())
  );

-- Replace the insert policy so writers can't spoof created_by
drop policy "writers can insert events" on public.home_events;

create policy "writers can insert events"
  on public.home_events
  for insert
  to authenticated
  with check (
    (select auth.jwt()) -> 'app_metadata' ->> 'role' = 'writer'
    and created_by = (select auth.uid())
  );
