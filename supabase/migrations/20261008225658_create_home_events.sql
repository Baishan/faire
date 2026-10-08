-- Append-only log of Home Assistant events
create table public.home_events (
  id           bigint      generated always as identity primary key,
  event_type   text        not null,
  entity_id    text        not null,
  payload      jsonb       not null default '{}'::jsonb,
  received_at  timestamptz not null default now(),

  constraint home_events_event_type_not_blank check (length(trim(event_type)) > 0),
  constraint home_events_entity_id_not_blank  check (length(trim(entity_id)) > 0)
);

comment on table public.home_events is
  'Events ingested from Home Assistant via the ingest-event edge function';

-- Latest events per entity (also used for "sensor gone quiet")
create index home_events_entity_received_idx
  on public.home_events (entity_id, received_at desc);

-- Event volume by type over time (dashboards)
create index home_events_type_received_idx
  on public.home_events (event_type, received_at desc);

-- No policies yet: deny all for anon/authenticated
alter table public.home_events enable row level security;
