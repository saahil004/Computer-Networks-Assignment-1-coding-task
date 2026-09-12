# DNS Resolver App — Design

**Date:** 2026-09-12
**Status:** Approved (brainstorming sections 1–3 approved in chat)
**Origin:** CS3001 Computer Networks, Assignment 1, Section A. The raw-socket DNS
client in `../assignment.py` is the CLI submission and stays untouched. This
project wraps the same packet-building/parsing logic in a FastAPI backend and a
Next.js frontend, both containerised, to demonstrate the protocol visually.

## 1. Goals

1. Reuse the CLI's `struct`-based header/question building and parsing as the
   core of the backend — no high-level resolver calls (`gethostbyname`,
   `dnspython`, etc.).
2. Fix the CLI's known parser bugs in the reused code:
   - answer records assumed to be 16 bytes (breaks on CNAME);
   - ANCOUNT ignored (authority section parsed as answers);
   - response transaction ID / QR bit never verified;
   - `socket.gaierror` / `OSError` uncaught (crash on bad server input).
3. Expose three teaching features: an annotated hex dump of both packets, a
   TTL-aware cache with HIT/MISS status, and per-query round-trip time.
4. `docker compose up --build` runs everything.

## 2. Non-goals

- Recursive/iterative resolution (root → TLD → authoritative). Queries go to a
  user-supplied recursive server with RD=1, exactly like the CLI.
- TCP fallback on TC=1, EDNS0, DNSSEC validation.
- Negative caching (NXDOMAIN is never cached).
- Query history, multi-server comparison, authentication, rate limiting.
- Persistence of any kind; the cache is in-process memory.

## 3. Repository layout

```
assignment1/
├── assignment.py                     CLI submission — untouched
├── dns_theory_recap.md
└── dns-resolver-app/                 this project (its own git repo)
    ├── docker-compose.yml
    ├── README.md
    ├── docs/superpowers/specs/       this document
    ├── backend/
    │   ├── Dockerfile
    │   ├── .dockerignore
    │   ├── pyproject.toml            deps + ruff + pytest config
    │   ├── app/
    │   │   ├── __init__.py
    │   │   ├── main.py               FastAPI app factory, lifespan, /health, error handlers
    │   │   ├── config.py             pydantic-settings
    │   │   ├── schemas.py            request/response/error models
    │   │   ├── api/
    │   │   │   ├── __init__.py
    │   │   │   └── resolve.py        POST /api/v1/resolve, DELETE /api/v1/cache
    │   │   ├── service.py            orchestrates cache → transport → parse → response model
    │   │   └── dns/
    │   │       ├── __init__.py
    │   │       ├── protocol.py       build/parse (reused CLI logic, fixed)
    │   │       ├── transport.py      UDP send/recv with timeout + RTT (reused CLI logic)
    │   │       ├── cache.py          TTL cache
    │   │       └── errors.py         DnsError hierarchy
    │   └── tests/
    │       ├── fixtures/             captured real packets as .hex files
    │       ├── test_protocol.py
    │       ├── test_transport.py
    │       ├── test_cache.py
    │       └── test_api.py
    └── frontend/
        ├── Dockerfile
        ├── .dockerignore
        ├── package.json
        ├── next.config.ts            output: 'standalone'
        └── src/
            ├── app/
            │   ├── layout.tsx
            │   ├── page.tsx          the single page
            │   └── api/[...path]/route.ts   runtime proxy → API_URL
            ├── components/           ResolveForm, StatusStrip, HeaderCard, QuestionCard,
            │                         RecordsTable, PacketInspector, ErrorCard
            └── lib/
                ├── api.ts            typed fetch wrapper + response types
                └── hexdump.ts        pure: bytes+spans → rows for rendering (unit-tested)
```

## 4. Backend

### 4.1 Stack

Python 3.13, FastAPI, Pydantic v2, pydantic-settings, uvicorn. Dev/test: pytest,
httpx (TestClient), ruff. Dependency management via `pyproject.toml` + `uv`
(inside Docker); plain `pip install -e .[dev]` also works locally.

### 4.2 `dns/protocol.py` — reused and fixed

Pure functions, no I/O. Names are the CLI's functions renamed to PEP8:

| CLI (`assignment.py`) | `protocol.py` | Change |
|---|---|---|
| `buildHeader(id, ...)` | `build_header(txid, flags=0x0100, qdcount=1)` | same `struct.pack("!HHHHHH", ...)` |
| `QNAME(domain)` | `encode_qname(domain) -> bytes` | same; raises `ValueError` on empty label or label > 63 |
| `QTYPE()/QCLASS()` | `QTYPE_A=1, QTYPE_AAAA=28, QCLASS_IN=1` + `struct.pack("!H", ...)` | `IPv4=False` no longer yields type 0 |
| `buildQuery(id, domain)` | `build_query(txid, domain, qtype) -> bytes` | qtype param |
| `parseHeader(data)` | `parse_header(data) -> Header` | same `struct.unpack("!HHHHHH", data[:12])`, flags decoded into fields |
| `getRCODE/typeRCODE` | `Flags.rcode`, `RCODE_NAMES` dict | same masks |
| `sliceAnswer/parseAnswers` | `parse_response(data) -> DnsMessage` | rewritten — see below |
| — | `decode_name(data, offset) -> (str, int)` | new: label walk + `0xC0` pointer following |

Data model (dataclasses, frozen):

```
Flags(raw, qr, opcode, aa, tc, rd, ra, ad, cd, rcode, rcode_name)
Header(txid, flags, qdcount, ancount, nscount, arcount)
Question(name, qtype, qclass)
ResourceRecord(name, rtype, rclass, ttl, rdlength, rdata: bytes, data: str)
Span(section, field, start, end, value: str)
DnsMessage(header, questions, answers, authority, additional, spans)
```

`parse_response(data)`:
1. `len(data) < 12` → `MalformedResponse("packet shorter than DNS header")`.
2. `parse_header`, record spans for the six header fields (`section="header"`).
3. Loop `qdcount` questions: `decode_name`, then `!HH`; spans `section="question"`.
4. Loop `ancount`, `nscount`, `arcount` records with `parse_record`; sections
   `"answer" | "authority" | "additional"`.
5. Trailing bytes after the last declared record → one span
   `section="trailing", field="unparsed"` (not an error).

`parse_record(data, offset)`:
- `name, offset = decode_name(data, offset)`
- `rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])`
- bounds check `offset + 10 + rdlength <= len(data)` else `MalformedResponse`
- `rdata = data[offset+10 : offset+10+rdlength]`
- `data` string by type:
  - `A` (1): `rdlength == 4` required → `"a.b.c.d"` (same 4×`!B` idea as the CLI)
  - `AAAA` (28): `rdlength == 16` required → `ipaddress.IPv6Address(rdata).compressed`
  - `CNAME` (5), `NS` (2), `PTR` (12): `decode_name(data, offset+10)` — pointers may
    reference anywhere in the message, so decode against the full packet
  - `SOA` (6): `mname`, `rname` via `decode_name`, then `!IIIII` → `"mname rname serial refresh retry expire minimum"`
  - anything else: `rdata.hex(" ")`
- returns `(ResourceRecord, next_offset)` where `next_offset = offset + 10 + rdlength`
  (**this is the CNAME fix**)

`decode_name(data, offset)`:
- walk labels; length byte `0` terminates; length `>= 0xC0` is a 2-byte pointer,
  offset = `((b0 & 0x3F) << 8) | b1`; first pointer encountered fixes the
  "next offset" as `pointer_pos + 2`; labels are decoded as ASCII (IDNA labels
  come back as `xn--…`, which is what was sent)
- guards: every read bounds-checked; more than 128 pointer jumps →
  `MalformedResponse("compression pointer loop")`; a label byte in `0x40–0xBF`
  → `MalformedResponse("unsupported label type")`
- returns `""` for the root name; otherwise dotted name without trailing dot

Type/class name tables: `RTYPE_NAMES = {1:"A", 2:"NS", 5:"CNAME", 6:"SOA",
12:"PTR", 15:"MX", 16:"TXT", 28:"AAAA"}`; unknown → `"TYPE{n}"`. Class:
`{1:"IN"}`; unknown → `"CLASS{n}"`.

### 4.3 `dns/transport.py` — reused

```
@dataclass(frozen=True)
class Exchange:
    request: bytes
    response: bytes
    server: tuple[str, int]
    rtt_ms: float

def send_query(request: bytes, server: str, port: int, timeout: float, expected_txid: int) -> Exchange
```

Synchronous, same shape as the CLI's `handleQuery`:
`socket(AF_INET, SOCK_DGRAM)` → `settimeout` → `sendto` → `recvfrom(4096)` → close
(via `with` so the socket is always closed, fixing the unbound-`s` edge case).

Differences from the CLI:
- Deadline loop: `recvfrom` runs until `time.monotonic()` passes the deadline.
  A datagram whose source address ≠ `(server, port)` or whose first two bytes ≠
  `expected_txid` is discarded and the loop continues (stale replies from a
  previous timed-out query, spoofed packets). Timeout on the socket is set to the
  remaining time on each iteration.
- RTT measured with `time.perf_counter()` from just before `sendto` to the
  accepted `recvfrom`.
- Error mapping (all subclasses of `DnsError` in `errors.py`):
  - `socket.timeout` / `TimeoutError` → `QueryTimeout(server, port, timeout)`
  - `ConnectionResetError` (Windows ICMP port-unreachable) and other `OSError`
    → `NetworkError(str(exc))`
  - `socket.gaierror` cannot occur because the API validates `server` as an
    IPv4 literal before calling; still caught under `OSError` for safety.
- `port` is a parameter so tests can hit a fake server on an ephemeral port;
  the API always passes 53.

Transaction IDs are generated by the service with `secrets.randbelow(65536)`.

### 4.4 `dns/cache.py`

```
class TtlCache:
    def __init__(self, max_entries: int = 1000, clock: Callable[[], float] = time.monotonic)
    def get(self, key: CacheKey) -> CacheHit | None
    def put(self, key: CacheKey, message: DnsMessage, exchange: Exchange) -> None
    def clear(self) -> None
    def __len__(self) -> int

CacheKey = tuple[str, int]            # (domain lower-cased, qtype)
CacheHit(message: DnsMessage, exchange: Exchange, ttl_remaining: int, age: int)
```

- `put` is a no-op unless `message.header.flags.rcode == 0 and message.answers`;
  expiry = `now + min(rr.ttl for rr in answers)`; a min TTL of 0 is not cached.
- `get` evicts and returns `None` if expired. Otherwise returns the stored
  message with every record's `ttl` replaced by `max(0, ttl - age)` across
  answers/authority/additional — the behaviour of a caching resolver. Spans are
  returned unchanged (they describe the original bytes).
- Capacity: on `put` when full, first drop all expired entries; if still full,
  drop the oldest inserted (`OrderedDict`).
- All methods hold a `threading.Lock` (endpoints run in the threadpool).
- Instance lives on `app.state.cache`, created in the lifespan.

### 4.5 `service.py`

```
def resolve(req: ResolveRequest, cache: TtlCache, settings: Settings) -> ResolveResponse
```

1. `key = (req.domain, qtype_code)`.
2. If not `req.bypass_cache` and `cache.get(key)` → build response with
   `cache.status="HIT"`, `ttl_remaining`, `timing.rtt_ms=None`.
3. Else `txid = secrets.randbelow(65536)`, `request = build_query(...)`,
   `exchange = send_query(request, req.server, 53, req.timeout, txid)`.
4. `message = parse_response(exchange.response)`; then validate
   `message.header.txid == txid` and `flags.qr` else `MalformedResponse`.
   (The transport already filters on txid bytes; this is the parse-level check
   and covers the QR bit.)
5. `cache.put(key, message, exchange)` (no-op for non-cacheable results).
6. Build `ResolveResponse` with `cache.status = "BYPASS" if req.bypass_cache else "MISS"`.

Query-packet spans are produced by `build_query_spans(domain, qtype)` in
`protocol.py` (header fields + qname labels + qtype + qclass) — deterministic
from the inputs, no parsing needed.

The route calls `service.resolve` via `starlette.concurrency.run_in_threadpool`.

### 4.6 API

`POST /api/v1/resolve` — request (`ResolveRequest`):

| field | type | rules |
|---|---|---|
| `domain` | str | normalised: strip whitespace, strip one trailing `.`, lower-case, IDNA-encode (`domain.encode("idna").decode()`); then each label 1–63 chars matching `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`, total ≤ 253, at least one label |
| `server` | str | must parse with `ipaddress.IPv4Address` |
| `qtype` | `"A" \| "AAAA"` | default `"A"` |
| `timeout` | float | `0.5 ≤ t ≤ 10`, default `settings.default_timeout` (5.0) |
| `bypass_cache` | bool | default `false` |

Response 200 (`ResolveResponse`):

```json
{
  "query":     {"domain": "www.example.com", "qtype": "A", "server": "8.8.8.8", "port": 53, "transaction_id": 31002},
  "header":    {"transaction_id": 31002,
                "flags": {"raw": 33152, "qr": true, "opcode": 0, "aa": false, "tc": false, "rd": true,
                          "ra": true, "ad": false, "cd": false, "rcode": 0, "rcode_name": "NOERROR"},
                "qdcount": 1, "ancount": 2, "nscount": 0, "arcount": 0},
  "question":  {"name": "www.example.com", "type": "A", "class": "IN"},
  "answers":   [{"name": "www.example.com", "type": "CNAME", "type_code": 5, "class": "IN",
                 "ttl": 300, "rdlength": 35, "data": "www.example.com-v4.edgesuite.net"},
                {"name": "www.example.com-v4.edgesuite.net", "type": "A", "type_code": 1, "class": "IN",
                 "ttl": 43, "rdlength": 4, "data": "93.184.216.34"}],
  "authority": [], "additional": [],
  "resolved_ips": ["93.184.216.34"],
  "timing":    {"rtt_ms": 23.4},
  "cache":     {"status": "MISS", "ttl_remaining": null},
  "packets":   {"query":    {"hex": "791a0100000100000000000003777777...", "spans": [ {"section":"header","field":"ID","start":0,"end":2,"value":"0x791a"}, "..." ]},
                "response": {"hex": "...", "spans": ["..."]}}
}
```

- `resolved_ips` = `data` of every answer whose type equals the requested qtype.
- `hex` is lower-case, no separators; the frontend formats it.
- `question` is the first echoed question; `qdcount` is reported as-is.
- RCODE names: `0 NOERROR, 1 FORMERR, 2 SERVFAIL, 3 NXDOMAIN, 4 NOTIMP, 5 REFUSED`,
  else `"RCODE{n}"`.

`DELETE /api/v1/cache` → `204`.
`GET /health` → `{"status": "ok", "cache_entries": n}`.

Errors — every non-2xx body is `{"error": "<code>", "detail": "<message>"}`:

| HTTP | `error` | when |
|---|---|---|
| 422 | `validation_error` | pydantic/validator failure; `detail` is the first human-readable message (e.g. `"server must be an IPv4 address"`) |
| 504 | `timeout` | `QueryTimeout` — `"No response from 8.8.8.8:53 within 5.0s"` |
| 502 | `malformed_response` | `MalformedResponse` |
| 503 | `network_error` | `NetworkError` |

Exception handlers are registered in `main.py` for `RequestValidationError`
and each `DnsError` subclass. CORS middleware is **not** enabled (single origin
via the frontend proxy); `settings.cors_origins` exists for local dev only
(default empty → middleware not added).

### 4.7 Configuration (`config.py`)

`Settings(BaseSettings)` with env prefix `DNS_`: `default_timeout=5.0`,
`cache_max_entries=1000`, `cors_origins: list[str] = []`, `log_level="INFO"`.

Logging: stdlib `logging`, one line per query at INFO:
`resolve domain=… qtype=… server=… rcode=… cache=… rtt_ms=…`.

## 5. Frontend

### 5.1 Stack

Next.js 15 (App Router), React 19, TypeScript strict, Tailwind CSS v4,
ESLint (next config), Vitest for `lib/hexdump.ts`. No data-fetching library;
`fetch` + `useState`.

### 5.2 Proxy route

`src/app/api/[...path]/route.ts` exports `GET`, `POST`, `DELETE`. Each forwards
to `${process.env.API_URL}/api/${path}` with the incoming method, body and
`content-type`, and returns the upstream status + body unchanged. `API_URL`
defaults to `http://localhost:8000` when unset (local dev). Read at request time,
so compose can set it at runtime.

### 5.3 Page structure (`page.tsx`, client component)

State: `{ status: "idle" | "loading" | "success" | "error", result?: ResolveResponse, error?: ApiError, lastRequest?: ResolveRequest }`.

Components:

- **ResolveForm** — domain text input (autofocus, Enter submits), server
  `<select>` with presets `8.8.8.8 Google`, `1.1.1.1 Cloudflare`, `9.9.9.9 Quad9`,
  `Custom…` (reveals a text input), A/AAAA segmented toggle, "Skip cache"
  checkbox, **Resolve** button (disabled while loading), **Clear cache** button
  (calls `DELETE`, shows a transient "cache cleared" note). Client-side
  pre-check only for empty fields; all real validation is the backend's 422.
- **StatusStrip** — RCODE badge (green `NOERROR`, red `NXDOMAIN`/`SERVFAIL`/
  `REFUSED`, amber others), cache badge (`MISS` grey, `HIT` amber with a live
  countdown of `ttl_remaining` seconds via `setInterval`, `BYPASS` blue), RTT
  (`23.4 ms` or `— (cached)`), transaction ID in hex + decimal, server.
- **HeaderCard** — flag chips `QR AA TC RD RA AD CD` lit when true, opcode,
  four counts.
- **QuestionCard** — name / type / class.
- **RecordsTable** — columns NAME · TYPE · CLASS · TTL · DATA. Rows whose type
  equals the queried type get a highlighted DATA cell. Answers always shown;
  Authority and Additional in collapsed `<details>` with counts (open by
  default when answers are empty, so an NXDOMAIN's SOA is visible).
- **PacketInspector** — tabs Query | Response. Rendered from
  `hexdump(bytes, spans)`: an offset column, 16 hex bytes, an ASCII column.
  Each byte cell carries `data-section` for colour (header / question / answer /
  authority / additional / trailing) and a `title`/hover tooltip
  `"{section} › {field} = {value}"`. Legend row underneath. Query tab shows
  packet size; Response tab also shows RTT.
- **ErrorCard** — maps `{error, detail}` to a heading (`Timeout`,
  `Malformed response`, `Network error`, `Invalid input`) with the detail text and
  a hint (e.g. timeout → "check the server IP or try a public resolver").

`lib/hexdump.ts` (pure, tested):
```
type Span = { section: string; field: string; start: number; end: number; value: string }
type Cell = { offset: number; byte: number; hex: string; ascii: string; span: Span | null }
type Row  = { offset: number; cells: Cell[] }
function hexToBytes(hex: string): Uint8Array
function hexdump(bytes: Uint8Array, spans: Span[], width = 16): Row[]
```
The backend emits field-level spans only, each carrying its `section`; every
byte of a well-formed packet is covered by exactly one span. If spans ever
overlap, the **last** one in the list wins. For a compressed NAME the span
`value` is rendered as `"→ 0x0c (www.example.com)"` so the pointer is visible.

### 5.4 Visual direction

Utility/monitor aesthetic: dark neutral background, monospace for anything
byte-level, a restrained accent per packet section. No decorative animation;
the countdown and loading state are the only motion. Works at 400px width
(form stacks, hex dump scrolls horizontally inside its own container).

## 6. Docker

### 6.1 `backend/Dockerfile`

```
FROM python:3.13-slim AS base
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY app ./app
RUN useradd -r -u 10001 app && chown -R app /app
USER app
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"
CMD ["uv", "run", "--no-sync", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
```
(`uv.lock` committed. Single worker is deliberate — see §4.4.)

### 6.2 `frontend/Dockerfile`

Standard three-stage Next standalone build: `deps` (`npm ci`), `builder`
(`npm run build` with `output: 'standalone'`), `runner` (`node:22-alpine`,
non-root `nextjs` user, copies `.next/standalone`, `.next/static`, `public`;
`CMD ["node", "server.js"]`, `EXPOSE 3000`). `API_URL` is *not* baked in — it's
read at request time by the proxy route.

### 6.3 `docker-compose.yml`

```yaml
services:
  backend:
    build: ./backend
    ports: ["8000:8000"]        # published so /docs is reachable for the demo
    environment:
      DNS_LOG_LEVEL: INFO
    healthcheck: inherits Dockerfile HEALTHCHECK
  frontend:
    build: ./frontend
    ports: ["3000:3000"]
    environment:
      API_URL: http://backend:8000
    depends_on:
      backend:
        condition: service_healthy
```

UDP egress from the backend container to `<server>:53` uses the default bridge
network; nothing special required.

## 7. Testing

### 7.1 Backend (`pytest`, run with `uv run pytest`)

- `test_protocol.py`
  - `build_query(0x1234, "www.example.com", 1)` equals a hand-written byte string.
  - `encode_qname` rejects empty labels and labels > 63 chars.
  - `decode_name`: plain name; name ending in a pointer; pointer to a pointer;
    self-referencing pointer → `MalformedResponse`; pointer past end →
    `MalformedResponse`.
  - `parse_response` on captured fixtures (`tests/fixtures/*.hex`, captured with
    a small script during implementation and committed):
    - `google_com_a.hex` — NOERROR, ≥1 A answer, all answers type A, spans cover
      `[0, len)` contiguously.
    - `www_microsoft_com_cname.hex` — first answer CNAME, last answer A, count
      matches ANCOUNT, `resolved` A data is a valid IPv4.
    - `nxdomain_soa.hex` — rcode 3, `answers == []`, one SOA in `authority`.
  - Truncated packet (fixture cut at 20 bytes) → `MalformedResponse`.
  - `< 12` bytes → `MalformedResponse`.
- `test_cache.py` with a fake clock: MISS then HIT; TTL decremented on HIT;
  expiry at `min TTL`; NXDOMAIN not cached; TTL 0 not cached; capacity eviction
  order; `clear()`.
- `test_transport.py` with a fake UDP server bound to `127.0.0.1:0` in a
  thread: happy path (echoes txid, returns canned packet, `rtt_ms > 0`);
  server replies with wrong txid first then right one → right one returned;
  server never replies → `QueryTimeout` within `timeout + 0.5s`.
- `test_api.py` with `TestClient` and `send_query` monkeypatched:
  200 shape on the CNAME fixture; 422 on `server="not-an-ip"`, `domain="a..b"`,
  `timeout=99`; 504/502/503 mapping; `DELETE /api/v1/cache` → 204 then next
  resolve is a MISS; IDNA: `"bücher.example"` is sent as `xn--bcher-kva.example`.
- Opt-in real network tests under `@pytest.mark.network`, skipped unless
  `--run-network` is passed.

### 7.2 Frontend

`npm run lint`, `npm run typecheck` (`tsc --noEmit`), `npm test` (Vitest):
`hexToBytes`, `hexdump` row splitting, last-span-wins lookup, ASCII rendering of
non-printables as `.`.

### 7.3 End-to-end (manual, documented in README)

`docker compose up --build`, open `http://localhost:3000`, resolve
`google.com`, `www.microsoft.com` (CNAME chain visible), `nu.edu.pk` or
another `.edu`, an NXDOMAIN, then repeat one to show a HIT with countdown.
These are also the screenshots the assignment asks for.

## 8. Reuse map for the report

The README will include a short table mapping each CLI function to its
`protocol.py`/`transport.py` counterpart (the table in §4.2) so the teacher can
see the assignment code is the core of the app rather than a library call.
