// ingest-event: accepts Home Assistant events authenticated by a per-client token.
// Callers send `x-ingest-token`; we look up its SHA-256 hash in public.ingest_clients.
// Every request emits exactly one JSON log line (see the wrapper in `export default`).

// Setup type definitions for built-in Supabase Runtime APIs
import "@supabase/functions-js/edge-runtime.d.ts";
import { type SupabaseContext, withSupabase } from "@supabase/server";

const TOKEN_HEADER = "x-ingest-token";

type LogFields = Record<string, unknown>;

type IngestClient = { id: number; name: string };

type EventInput = {
  event_type: string;
  entity_id: string;
  payload: Record<string, unknown>;
};

// ---------------------------------------------------------------------------
// Errors: throw these from anywhere in the handler; the wrapper turns them
// into a response + log fields. `reason` is for logs, `message` is for callers.
// ---------------------------------------------------------------------------

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly reason: string,
    readonly publicMessage: string,
    readonly details: LogFields = {},
  ) {
    super(reason);
  }
}

const methodNotAllowed = () =>
  new HttpError(405, "method_not_allowed", "method not allowed");

// Same public message for every auth failure: don't tell callers why.
const unauthorized = (reason: string) =>
  new HttpError(401, reason, "unauthorized");

const badRequest = (reason: string, message: string) =>
  new HttpError(400, reason, message);

// DB error details go to the logs only, never to the caller.
const internalError = (reason: string, err?: { code?: string; message?: string }) =>
  new HttpError(500, reason, "internal error", {
    db_code: err?.code,
    db_message: err?.message,
  });

const OUTCOMES: Record<number, string> = {
  201: "ok",
  400: "bad_request",
  401: "unauthorized",
  405: "method_not_allowed",
};
const outcomeFor = (status: number) => OUTCOMES[status] ?? "error";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const json = (status: number, body: unknown) => Response.json(body, { status });

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const isNonEmptyString = (v: unknown): v is string =>
  typeof v === "string" && v.trim().length > 0;

// ---------------------------------------------------------------------------
// Entry point: timing, error mapping and the single log line
// ---------------------------------------------------------------------------

export default {
  // auth: "none" — we authenticate the caller ourselves via ingest_clients.
  // ctx.supabaseAdmin bypasses RLS, so only use it after the token check.
  fetch: withSupabase({ auth: "none" }, async (req, ctx) => {
    const start = performance.now();
    const log: LogFields = { msg: "ingest" };
    let res: Response;

    try {
      res = await handle(req, ctx, log);
    } catch (err) {
      if (err instanceof HttpError) {
        Object.assign(log, { reason: err.reason }, err.details);
        res = json(err.status, { error: err.publicMessage });
      } else {
        // Anything unexpected still gets logged and returns a clean 500
        Object.assign(log, { reason: "unhandled_exception", error: String(err) });
        res = json(500, { error: "internal error" });
      }
    }

    log.status = res.status;
    log.outcome = outcomeFor(res.status);
    log.duration_ms = Math.round(performance.now() - start);

    (res.status >= 500 ? console.error : console.log)(JSON.stringify(log));
    return res;
  }),
};

// ---------------------------------------------------------------------------
// Handler: the actual logic, straight-line. Failures throw HttpError.
// ---------------------------------------------------------------------------

async function handle(
  req: Request,
  ctx: SupabaseContext,
  log: LogFields,
): Promise<Response> {
  if (req.method !== "POST") throw methodNotAllowed();

  // 1. Authenticate before doing any other work
  const client = await authenticate(req, ctx);
  log.client = client.name;

  // 2. Parse and validate
  const input = await parseEvent(req);
  log.event_type = input.event_type;
  log.entity_id = input.entity_id;

  // 3. Store
  const id = await insertEvent(ctx, client, input);
  log.event_id = id;

  return json(201, { id });
}

async function authenticate(
  req: Request,
  ctx: SupabaseContext,
): Promise<IngestClient> {
  const token = req.headers.get(TOKEN_HEADER);
  if (!token) throw unauthorized("missing_token");

  const { data, error } = await ctx.supabaseAdmin
    .from("ingest_clients")
    .select("id, name")
    .eq("token_hash", await sha256Hex(token))
    .is("revoked_at", null)
    .maybeSingle();

  if (error) throw internalError("client_lookup_failed", error);
  if (!data) throw unauthorized("unknown_token");

  return data;
}

async function parseEvent(req: Request): Promise<EventInput> {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    throw badRequest("invalid_json", "body must be valid json");
  }
  if (!isPlainObject(body)) {
    throw badRequest("body_not_object", "body must be an object");
  }

  const { event_type, entity_id, payload = {} } = body;
  if (!isNonEmptyString(event_type)) {
    throw badRequest("missing_event_type", "event_type is required");
  }
  if (!isNonEmptyString(entity_id)) {
    throw badRequest("missing_entity_id", "entity_id is required");
  }
  if (!isPlainObject(payload)) {
    throw badRequest("payload_not_object", "payload must be an object");
  }

  return { event_type, entity_id, payload };
}

async function insertEvent(
  ctx: SupabaseContext,
  client: IngestClient,
  input: EventInput,
): Promise<number> {
  // Insert only the validated fields
  const { data, error } = await ctx.supabaseAdmin
    .from("home_events")
    .insert({ ...input, client_id: client.id })
    .select("id")
    .single();

  if (error) throw internalError("insert_failed", error);

  return data.id;
}

/* To invoke locally:

  1. `supabase start` and `supabase functions serve`
  2. Use the seeded local-test client token:

  curl -i -X POST 'http://127.0.0.1:54321/functions/v1/ingest-event' \
    -H 'x-ingest-token: faire_ing_localdev' \
    -H 'Content-Type: application/json' \
    -d '{"event_type":"door_opened","entity_id":"binary_sensor.front_door","payload":{"state":"on"}}'
*/
