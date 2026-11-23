# Route 53 tool build plan (learning guide)

A step-by-step order for building the Route 53 tools yourself. Do the steps in
order. Each step says what to build, what to verify, and the gotcha that will
bite you if you skip it. Do not move to the next step until the current one runs
and you have read its real output.

This file is a guide, not code. Write the code yourself.

---

## The one rule that makes this work

Build one function, run it standalone, read the REAL output, then design the
next function against what you actually got back, not against what you assume the
API returns. Every tool here can be run on its own with:

    python -m tracerai.tools.route53

Point the `__main__` block at whatever function you are currently testing.

---

## Step 0 - Understand the two layers before you write anything

- [ ] A tool is a plain Python function in `tracerai/tools/` that calls boto3 and
      returns a dict. No AI in it.
- [ ] The model only sees the `@tool` wrapper in `agent.py`, and only its
      docstring. The docstring is the interface to the model.
- [ ] You build and test the plain function FIRST. You wire the wrapper LAST,
      once the function already works.

Why: if the function is wrong, no prompt or model can save it. Get the data
right, then expose it.

---

## Step 1 - list_hosted_zones (do this first, it is the dependency)

Records live inside a zone, so you cannot list records without a zone id. That
is why zones come first: it is a hard dependency, not just ordering.

- [ ] Call the Route 53 list-hosted-zones API (it paginates, use the paginator).
- [ ] Return, per zone: zone id, name, private-or-public, record count.
- [ ] Normalize the id: the API returns `/hostedzone/Z123`; strip it to `Z123`
      so callers can pass the bare id back in.
- [ ] Run it. Read the output. Confirm you see your real zones and that the
      private flag is correct for your private hosted zones.

Verify you understand: which of your zones are private (the ones that matter for
VPC DNS), and what their ids are. You will paste one into Step 2.

Gotcha: Route 53 (zones, records, health checks) is a GLOBAL service. No region.
Pin the client to us-east-1. Contrast this later with the Resolver tool, which IS
regional.

---

## Step 2 - describe_records (the rich one)

This is where your six questions (alias, evaluate target health, routing policy,
type, health check) all get answered, because they are all fields of a record
set. One rich tool, not six thin ones.

### 2a - Decide the inputs first

- [ ] Zone identifier: REQUIRED. Accept a zone id (preferred) or a zone name.
      Without it there is nothing to list.
- [ ] Record name: OPTIONAL filter. If given, show only that record. If not,
      return the whole zone. So the tool works as both "dump the zone" and "show
      me app.internal".
- [ ] Record type: OPTIONAL second filter (A, AAAA, CNAME, MX, ...).

### 2b - Resolve a zone name to an id

The user will almost never give you a zone id, they give a name.

- [ ] If the caller gave a name not an id, look it up in the zone list and map it
      to an id.
- [ ] Trailing-dot gotcha: Route 53 stores names as `app.internal.` with a dot.
      If the user typed `app.internal`, add the dot before you compare or you
      match nothing (a silent empty result, the worst kind of bug).
- [ ] Split-horizon gotcha: the same name can exist as a PUBLIC and a PRIVATE
      zone. If a name resolves to two zones, do not guess; return both ids and
      ask which. (This is your WB15 Objective B scenario.)

### 2c - List the record sets

- [ ] Call list-resource-record-sets for the zone id (it paginates).
- [ ] Apply the optional record-name filter (remember the trailing dot) and the
      optional type filter.

### 2d - Summarize each record (the real intelligence)

For each record set, pull out the fields a human actually asks about:

- [ ] name and type. Note: the same name can have several types, and weighted or
      failover records share the same name AND type, told apart only by a
      SetIdentifier. So "the record for app.internal" may be several record sets.
- [ ] routing policy. Route 53 has NO policy field. You INFER it from which
      attribute is present: a Weight means weighted, a Region means latency, a
      GeoLocation means geolocation, a GeoProximityLocation means geoproximity, a
      Failover means failover, a MultiValueAnswer means multivalue, and no
      SetIdentifier at all means simple. This inference is the core Route 53
      knowledge in the whole tool; get it right.
- [ ] is-alias. An alias record changes the SHAPE of the answer: it has no TTL
      and no plain values; instead it has a target (a DNS name plus the target
      zone id). A normal record carries its answers in ResourceRecords.
- [ ] evaluate-target-health. This lives INSIDE the alias block, because it only
      exists on alias records. It changes behavior (whether the alias follows the
      target's health), so surface it whenever the record is an alias.
- [ ] health check id, when one is attached. Surface the id only. Do NOT read
      whether it is healthy here (that is Step 3, a different API).
- [ ] per-policy specifics: the weight, or the latency region, or the geo
      location, or the failover role (PRIMARY / SECONDARY). Include only the one
      that applies so the dict stays small.

- [ ] Run it against one real private zone from Step 1. Read the output. Find a
      record and confirm the routing policy and alias fields match what you see
      in the console.

---

## Step 3 - check_health_check (separate tool, on purpose)

Reading whether a health check is currently healthy is a DIFFERENT API, it is
slower, and not every record has one. So it is its own tool. describe_records
tells you WHICH check is attached; this tells you its STATE.

- [ ] Read the health check config (type, target, port, interval, failure
      threshold, inverted).
- [ ] Read the live status: the per-checker observations.
- [ ] Route 53 does NOT give you a single healthy boolean. Compute one: healthy
      when every checker reports a status starting with "Success".
- [ ] Be honest when you cannot: a CALCULATED or CLOUDWATCH_METRIC health check
      returns no endpoint observations, so there is nothing to score. Say that,
      do not report false health.

- [ ] Run it against a health check id you saw on a record in Step 2.

---

## Step 4 - Wire the three tools into agent.py (do this LAST)

Only now that the functions work. Three edits, copy the shape of an existing
tool like get_vpc_route_tables:

- [ ] Import each plain function at the top of agent.py.
- [ ] Write one `@tool` wrapper per function. The docstring is written FOR THE
      MODEL: say when to use it, what inputs it needs, and what it returns. This
      is the skill, spend time here.
- [ ] Add the three wrappers to the `tools=[...]` list in build_agent().
- [ ] Start the agent and ask it a Route 53 question. Watch which tool it calls.

---

## Step 5 - Extensions to write solo (this is where it clicks)

- [ ] check_resolver: outbound and inbound Resolver endpoints plus forwarding
      rules. route53resolver is REGIONAL, so this one DOES take a region. Writing
      the regional sibling from scratch teaches the global-vs-regional split.
- [ ] diagnose_dns: the capstone. Chain describe_records, then for any record
      with a health check id call check_health_check, and return a verdict like
      "this record is failover PRIMARY, its health check is UNHEALTHY, so traffic
      is going to SECONDARY". Chaining tools into a verdict is where an agent
      earns its keep.
- [ ] DNS Firewall rule groups and domain lists on a VPC (ties to WB18).
- [ ] Hosted zone VPC associations: which VPCs a private zone serves (the
      split-horizon question).

---

## Checklist of the gotchas (the stuff that silently breaks)

- [ ] Global service: no region, pin to us-east-1. Resolver is the exception.
- [ ] Zone id comes back as /hostedzone/Z123; strip to Z123.
- [ ] Record names have a trailing dot; add it before comparing.
- [ ] Split-horizon: one name, two zones (public + private). Disambiguate.
- [ ] Routing policy is inferred from which field is present, never stated.
- [ ] evaluate-target-health is alias-only; it lives in the alias block.
- [ ] Health check has no healthy boolean; compute it, and admit when a
      calculated or CloudWatch check gives you nothing to score.
- [ ] Wrap every API call so a missing permission becomes a note, not a crash.
- [ ] Return structured fields, not prose. Let the model phrase it.
