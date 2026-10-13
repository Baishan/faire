// ingest-event: accepts Home Assistant events authenticated by a per-client token.
// Callers send `x-ingest-token`; we look up its SHA-256 hash in public.ingest_clients.

// Setup type definitions for built-in Supabase Runtime APIs
import "@supabase/functions-js/edge-runtime.d.ts";
import { withSupabase } from "@supabase/server";

const TOKEN_HEADER = "x-ingest-token";

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

export default {
  // auth: "none" — we authenticate the caller ourselves via ingest_clients.
  // ctx.supabaseAdmin bypasses RLS, so only use it after the token check.
  fetch: withSupabase({ auth: "none" }, async (req, ctx) => {
    if (req.method !== "POST") {
      return json(405, { error: "method not allowed" });
    }

    // 1. Authenticate before doing any other work
    const token = req.headers.get(TOKEN_HEADER);
    if (!token) {
      return json(401, { error: "unauthorized" });
    }

    const { data: client, error: clientError } = await ctx.supabaseAdmin
      .from("ingest_clients")
      .select("id, name")
      .eq("token_hash", await sha256Hex(token))
      .is("revoked_at", null)
      .maybeSingle();

    if (clientError) {
      console.error("client lookup failed", clientError);
      return json(500, { error: "internal error" });
    }
    if (!client) {
      return json(401, { error: "unauthorized" }); // same response as missing token
    }

    // 2. Parse and validate
    let body: unknown;
    try {
      body = await req.json();
    } catch {
      return json(400, { error: "body must be valid json" });
    }
    if (!isPlainObject(body)) {
      return json(400, { error: "body must be an object" });
    }

    const { event_type, entity_id, payload = {} } = body;
    if (!isNonEmptyString(event_type)) {
      return json(400, { error: "event_type is required" });
    }
    if (!isNonEmptyString(entity_id)) {
      return json(400, { error: "entity_id is required" });
    }
    if (!isPlainObject(payload)) {
      return json(400, { error: "payload must be an object" });
    }

    // 3. Insert only the validated fields
    const { data: event, error: insertError } = await ctx.supabaseAdmin
      .from("home_events")
      .insert({ event_type, entity_id, payload, client_id: client.id })
      .select("id")
      .single();

    if (insertError) {
      console.error("insert failed", insertError);
      return json(500, { error: "internal error" });
    }

    return json(201, { id: event.id });
  }),
};

/* To invoke locally:

  1. `supabase start` and `supabase functions serve`
  2. Use the seeded local-test client token:

  curl -i -X POST 'http://127.0.0.1:54321/functions/v1/ingest-event' \
    -H 'x-ingest-token: faire_ing_localdev' \
    -H 'Content-Type: application/json' \
    -d '{"event_type":"door_opened","entity_id":"binary_sensor.front_door","payload":{"state":"on"}}'
*/
