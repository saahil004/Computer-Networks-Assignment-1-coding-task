# DNS Resolver App Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wrap the raw-socket DNS client from `assignment.py` in a FastAPI backend and a Next.js frontend that show the parsed response, an annotated hex dump, a TTL cache HIT/MISS, and RTT — all runnable with `docker compose up --build`.

**Architecture:** `backend/app/dns/protocol.py` holds the CLI's `struct`-based build/parse logic (renamed, bug-fixed); `transport.py` does the UDP exchange; `cache.py` is an in-process TTL cache; `service.py` orchestrates and FastAPI exposes `POST /api/v1/resolve`. The Next.js app calls the backend through a runtime proxy route (`/api/[...path]`) so the browser sees one origin. Two Docker images, one compose file.

**Tech Stack:** Python 3.13, FastAPI, Pydantic v2, pydantic-settings, uvicorn, pytest, httpx, ruff, uv · Next.js (App Router), React, TypeScript, Tailwind v4, Vitest · Docker Compose.

**Spec:** `dns-resolver-app/docs/superpowers/specs/2026-09-12-dns-resolver-app-design.md`

## Global Constraints

- Git root is `assignment1/` (one level above `dns-resolver-app/`). All paths below are relative to `dns-resolver-app/` unless a command says otherwise. `assignment.py` and `dns_theory_recap.md` in the git root are **never modified**.
- No resolver libraries or `socket.gethostbyname`/`getaddrinfo` for the lookup itself — the query bytes are built with `struct` and sent over a UDP socket to port **53** (constant `DNS_PORT = 53` in `service.py`; the transport's `port` parameter exists only so tests can target a fake server).
- Python `>=3.13`; run every Python command through `uv run …` from `backend/` so the `.venv` is used.
- Backend runs a **single** uvicorn worker (the cache is per-process).
- Request validation limits (copied from spec §4.6): labels 1–63 chars matching `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`, total domain ≤ 253, `server` must parse as IPv4, `timeout` in `[0.5, 10]`, `qtype ∈ {"A", "AAAA"}`.
- Error body shape for every non-2xx: `{"error": "<code>", "detail": "<message>"}` with codes `validation_error` (422), `timeout` (504), `malformed_response` (502), `network_error` (503).
- Cache key is `(domain, qtype_code)`; only `rcode == 0` responses with ≥1 answer and min TTL > 0 are cached.
- Commit after every task with the trailer `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.
- Windows dev machine (PowerShell/Git Bash). Line endings: let git handle it; don't add `.gitattributes` work to any task.

---

### Task 1: Backend scaffold, error types, tooling

**Files:**
- Create: `backend/pyproject.toml`
- Create: `backend/app/__init__.py`, `backend/app/dns/__init__.py`, `backend/app/api/__init__.py` (all empty)
- Create: `backend/app/dns/errors.py`
- Create: `backend/tests/__init__.py` (empty), `backend/tests/conftest.py`
- Test: `backend/tests/test_errors.py`

**Interfaces:**
- Produces: `app.dns.errors.DnsError`, `QueryTimeout(server: str, port: int, timeout: float)`, `MalformedResponse(msg)`, `NetworkError(msg)`; pytest fixture `load_fixture(name: str) -> bytes` and the `--run-network` option / `network` marker.

- [ ] **Step 1: Install uv (once, on the dev machine)**

Run from anywhere: `python -m pip install --user uv` then `uv --version` — expected: a version string. If `uv` is not on PATH afterwards, use `python -m uv` in place of `uv` for every command in this plan.

- [ ] **Step 2: Write `backend/pyproject.toml`**

```toml
[project]
name = "dns-resolver-backend"
version = "0.1.0"
description = "Raw-socket DNS resolver API (CS3001 Assignment 1)"
requires-python = ">=3.13"
dependencies = [
    "fastapi>=0.115",
    "uvicorn[standard]>=0.30",
    "pydantic>=2.8",
    "pydantic-settings>=2.4",
]

[dependency-groups]
dev = [
    "pytest>=8.3",
    "httpx>=0.27",
    "ruff>=0.6",
]

[tool.uv]
package = false

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["."]
addopts = "-q"
markers = ["network: hits real DNS servers; enable with --run-network"]

[tool.ruff]
line-length = 100
target-version = "py313"

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP"]
```

- [ ] **Step 3: Create the package skeleton and `errors.py`**

Create empty files `backend/app/__init__.py`, `backend/app/dns/__init__.py`, `backend/app/api/__init__.py`, `backend/tests/__init__.py`.

`backend/app/dns/errors.py`:

```python
"""Exception hierarchy for the DNS client. The API maps each subclass to an HTTP status."""


class DnsError(Exception):
    """Base class for every failure the DNS client can raise."""


class QueryTimeout(DnsError):
    """The server did not answer within the deadline (HTTP 504)."""

    def __init__(self, server: str, port: int, timeout: float) -> None:
        self.server = server
        self.port = port
        self.timeout = timeout
        super().__init__(f"No response from {server}:{port} within {timeout:g}s")


class MalformedResponse(DnsError):
    """The bytes received could not be parsed as the DNS response we expected (HTTP 502)."""


class NetworkError(DnsError):
    """The OS refused to send/receive: unreachable host, ICMP port unreachable, ... (HTTP 503)."""
```

- [ ] **Step 4: Write `backend/tests/conftest.py`**

```python
import pathlib

import pytest

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-network",
        action="store_true",
        default=False,
        help="run tests marked 'network' (they hit real DNS servers)",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--run-network"):
        return
    skip = pytest.mark.skip(reason="needs --run-network")
    for item in items:
        if "network" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def load_fixture():
    """Return a loader for captured packets stored as hex text in tests/fixtures/."""

    def _load(name: str) -> bytes:
        return bytes.fromhex((FIXTURES / name).read_text(encoding="ascii").strip())

    return _load
```

- [ ] **Step 5: Write the failing test `backend/tests/test_errors.py`**

```python
import pytest

from app.dns.errors import DnsError, MalformedResponse, NetworkError, QueryTimeout


def test_query_timeout_message_and_attributes():
    exc = QueryTimeout("8.8.8.8", 53, 5.0)
    assert str(exc) == "No response from 8.8.8.8:53 within 5s"
    assert (exc.server, exc.port, exc.timeout) == ("8.8.8.8", 53, 5.0)


@pytest.mark.parametrize("cls", [QueryTimeout, MalformedResponse, NetworkError])
def test_all_errors_are_dns_errors(cls):
    assert issubclass(cls, DnsError)
```

- [ ] **Step 6: Install dependencies and run the test**

Run from `backend/`: `uv sync` (creates `.venv` and `uv.lock`), then `uv run pytest tests/test_errors.py -v`
Expected: 4 tests PASS. Then `uv run ruff check . && uv run ruff format --check .` — expected: no errors (run `uv run ruff format .` if it reports formatting).

- [ ] **Step 7: Commit**

Run from the git root (`assignment1/`):
```bash
git add dns-resolver-app/backend
git commit -m "feat(backend): scaffold project, error types, pytest config

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: `protocol.py` — query building (reused from the CLI)

**Files:**
- Create: `backend/app/dns/protocol.py`
- Test: `backend/tests/test_protocol.py`

**Interfaces:**
- Produces: constants `HEADER_LEN=12`, `HEADER_FMT="!HHHHHH"`, `FLAG_RD=0x0100`, `QTYPE_A=1`, `QTYPE_NS=2`, `QTYPE_CNAME=5`, `QTYPE_SOA=6`, `QTYPE_PTR=12`, `QTYPE_MX=15`, `QTYPE_TXT=16`, `QTYPE_AAAA=28`, `QCLASS_IN=1`; functions `rtype_name(code:int)->str`, `rclass_name(code:int)->str`, `rcode_name(code:int)->str`; dataclass `Span(section:str, field:str, start:int, end:int, value:str)`; `build_header(txid, flags=FLAG_RD, qdcount=1, ancount=0, nscount=0, arcount=0) -> bytes`; `encode_qname(domain:str) -> bytes`; `build_query(txid:int, domain:str, qtype:int=QTYPE_A) -> bytes`; `build_query_spans(txid:int, domain:str, qtype:int=QTYPE_A) -> list[Span]`.

- [ ] **Step 1: Write the failing tests**

`backend/tests/test_protocol.py`:

```python
import pytest

from app.dns.protocol import (
    QTYPE_A,
    QTYPE_AAAA,
    Span,
    build_header,
    build_query,
    build_query_spans,
    encode_qname,
    rcode_name,
    rtype_name,
)

# --- building (the CLI's buildHeader / QNAME / buildQuery) ---------------------------------


def test_build_header_matches_cli_layout():
    # ID=0x1234, flags=RD only, QDCOUNT=1, AN/NS/AR = 0  (same struct.pack("!HHHHHH") as the CLI)
    assert build_header(0x1234) == b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"


def test_encode_qname_length_prefixed_labels():
    assert encode_qname("www.example.com") == b"\x03www\x07example\x03com\x00"


@pytest.mark.parametrize("bad", ["www..example.com", "a" * 64 + ".com"])
def test_encode_qname_rejects_invalid_labels(bad):
    with pytest.raises(ValueError):
        encode_qname(bad)


def test_build_query_matches_hand_encoded_bytes():
    expected = (
        b"\x12\x34"  # ID
        b"\x01\x00"  # flags: RD=1
        b"\x00\x01\x00\x00\x00\x00\x00\x00"  # QDCOUNT=1, ANCOUNT=NSCOUNT=ARCOUNT=0
        b"\x03www\x07example\x03com\x00"  # QNAME
        b"\x00\x01"  # QTYPE A
        b"\x00\x01"  # QCLASS IN
    )
    assert build_query(0x1234, "www.example.com", QTYPE_A) == expected


def test_build_query_aaaa_sets_qtype_28():
    packet = build_query(1, "example.com", QTYPE_AAAA)
    assert packet[-4:-2] == b"\x00\x1c"


def test_build_query_spans_cover_the_whole_query_contiguously():
    packet = build_query(0x1234, "www.example.com")
    spans = build_query_spans(0x1234, "www.example.com")
    assert spans[0] == Span("header", "ID", 0, 2, "0x1234")
    assert [s.section for s in spans[:6]] == ["header"] * 6
    # spans are contiguous and end exactly at the packet length
    for prev, nxt in zip(spans, spans[1:], strict=False):
        assert prev.end == nxt.start
    assert spans[-1].end == len(packet)
    assert spans[-2].field == "QTYPE" and spans[-2].value == "A"


def test_name_tables():
    assert rtype_name(1) == "A" and rtype_name(5) == "CNAME" and rtype_name(999) == "TYPE999"
    assert rcode_name(3) == "NXDOMAIN" and rcode_name(9) == "RCODE9"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run from `backend/`: `uv run pytest tests/test_protocol.py -v`
Expected: ImportError — `app.dns.protocol` does not exist.

- [ ] **Step 3: Write `backend/app/dns/protocol.py` (build half)**

```python
"""DNS wire format (RFC 1035 §4) — building queries and parsing responses.

This is the packet logic from the CLI ``assignment.py`` renamed to PEP 8 and fixed:
records are walked by RDLENGTH, compression pointers are followed, and the header's
section counts are honoured. No I/O happens here.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

HEADER_LEN = 12
HEADER_FMT = "!HHHHHH"  # ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT

FLAG_RD = 0x0100  # recursion desired — the only flag a query sets

QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_SOA = 6
QTYPE_PTR = 12
QTYPE_MX = 15
QTYPE_TXT = 16
QTYPE_AAAA = 28
QCLASS_IN = 1

RTYPE_NAMES = {
    QTYPE_A: "A",
    QTYPE_NS: "NS",
    QTYPE_CNAME: "CNAME",
    QTYPE_SOA: "SOA",
    QTYPE_PTR: "PTR",
    QTYPE_MX: "MX",
    QTYPE_TXT: "TXT",
    QTYPE_AAAA: "AAAA",
}
RCLASS_NAMES = {QCLASS_IN: "IN"}
RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def rtype_name(code: int) -> str:
    return RTYPE_NAMES.get(code, f"TYPE{code}")


def rclass_name(code: int) -> str:
    return RCLASS_NAMES.get(code, f"CLASS{code}")


def rcode_name(code: int) -> str:
    return RCODE_NAMES.get(code, f"RCODE{code}")


@dataclass(frozen=True)
class Span:
    """A labelled byte range [start, end) inside a packet — feeds the frontend hex dump."""

    section: str  # header | question | answer | authority | additional | trailing
    field: str
    start: int
    end: int
    value: str


# --- building ----------------------------------------------------------------------------


def build_header(
    txid: int,
    flags: int = FLAG_RD,
    qdcount: int = 1,
    ancount: int = 0,
    nscount: int = 0,
    arcount: int = 0,
) -> bytes:
    return struct.pack(HEADER_FMT, txid, flags, qdcount, ancount, nscount, arcount)


def encode_qname(domain: str) -> bytes:
    """Length-prefixed labels, no dots, zero byte terminator: 'a.bc' -> b'\\x01a\\x02bc\\x00'."""
    qname = b""
    for label in domain.split("."):
        if not label:
            raise ValueError("empty label in domain name")
        if len(label) > 63:
            raise ValueError(f"label longer than 63 octets: {label!r}")
        qname += struct.pack("!B", len(label)) + label.encode("ascii")
    return qname + struct.pack("!B", 0)


def build_query(txid: int, domain: str, qtype: int = QTYPE_A) -> bytes:
    return build_header(txid) + encode_qname(domain) + struct.pack("!HH", qtype, QCLASS_IN)


def build_query_spans(txid: int, domain: str, qtype: int = QTYPE_A) -> list[Span]:
    """Byte annotations for a packet produced by build_query with the same arguments."""
    spans = [
        Span("header", "ID", 0, 2, f"0x{txid:04x}"),
        Span("header", "FLAGS", 2, 4, f"0x{FLAG_RD:04x} RD"),
        Span("header", "QDCOUNT", 4, 6, "1"),
        Span("header", "ANCOUNT", 6, 8, "0"),
        Span("header", "NSCOUNT", 8, 10, "0"),
        Span("header", "ARCOUNT", 10, 12, "0"),
    ]
    pos = HEADER_LEN
    for label in domain.split("."):
        spans.append(Span("question", "QNAME label", pos, pos + 1 + len(label), f"{len(label)} {label!r}"))
        pos += 1 + len(label)
    spans.append(Span("question", "QNAME end", pos, pos + 1, "0"))
    pos += 1
    spans.append(Span("question", "QTYPE", pos, pos + 2, rtype_name(qtype)))
    spans.append(Span("question", "QCLASS", pos + 2, pos + 4, rclass_name(QCLASS_IN)))
    return spans
```

- [ ] **Step 4: Run the tests to verify they pass**

Run from `backend/`: `uv run pytest tests/test_protocol.py -v`
Expected: all PASS. Then `uv run ruff check . && uv run ruff format .`

- [ ] **Step 5: Commit**

```bash
git add dns-resolver-app/backend
git commit -m "feat(backend): DNS query building reused from the CLI

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: `protocol.py` — header parsing and flag decoding

**Files:**
- Modify: `backend/app/dns/protocol.py` (append after the build section)
- Test: `backend/tests/test_protocol.py` (append)

**Interfaces:**
- Produces: `Flags(raw, qr, opcode, aa, tc, rd, ra, ad, cd, rcode)` with property `rcode_name`, method `describe() -> str`, and classmethod `Flags.from_raw(raw:int)`; `Header(txid, flags: Flags, qdcount, ancount, nscount, arcount)`; `parse_header(data: bytes) -> Header` raising `MalformedResponse` if `len(data) < 12`.

- [ ] **Step 1: Append the failing tests**

Append to `backend/tests/test_protocol.py` (and add `Flags, Header, parse_header` to the `app.dns.protocol` import plus `from app.dns.errors import MalformedResponse` at the top):

```python
# --- header parsing (the CLI's parseHeader / getRCODE / typeRCODE) ---------------------------


def test_parse_header_decodes_flags():
    # 0x8180 = QR RD RA, rcode 0
    header = parse_header(bytes.fromhex("791a 8180 0001 0002 0000 0000"))
    assert header == Header(
        txid=0x791A,
        flags=Flags(
            raw=0x8180, qr=True, opcode=0, aa=False, tc=False, rd=True, ra=True,
            ad=False, cd=False, rcode=0,
        ),
        qdcount=1,
        ancount=2,
        nscount=0,
        arcount=0,
    )
    assert header.flags.rcode_name == "NOERROR"
    assert header.flags.describe() == "0x8180 QR RD RA RCODE=NOERROR"


def test_parse_header_nxdomain_and_aa():
    # 0x8583 = QR AA RD RA, rcode 3
    flags = parse_header(bytes.fromhex("0000 8583 0001 0000 0001 0000")).flags
    assert flags.aa and flags.rcode == 3 and flags.rcode_name == "NXDOMAIN"


def test_parse_header_rejects_short_packet():
    with pytest.raises(MalformedResponse):
        parse_header(b"\x00" * 11)
```

- [ ] **Step 2: Run to verify failure**

Run from `backend/`: `uv run pytest tests/test_protocol.py -v` — expected: ImportError for `Flags`.

- [ ] **Step 3: Append the implementation to `protocol.py`**

Add `from app.dns.errors import MalformedResponse` to the imports, then append:

```python
# --- header parsing ----------------------------------------------------------------------


@dataclass(frozen=True)
class Flags:
    """The 16 flag bits: QR·Opcode(4)·AA·TC·RD·RA·Z·AD·CD·RCODE(4)."""

    raw: int
    qr: bool
    opcode: int
    aa: bool
    tc: bool
    rd: bool
    ra: bool
    ad: bool
    cd: bool
    rcode: int

    @property
    def rcode_name(self) -> str:
        return rcode_name(self.rcode)

    @classmethod
    def from_raw(cls, raw: int) -> Flags:
        return cls(
            raw=raw,
            qr=bool(raw & 0x8000),
            opcode=(raw >> 11) & 0xF,
            aa=bool(raw & 0x0400),
            tc=bool(raw & 0x0200),
            rd=bool(raw & 0x0100),
            ra=bool(raw & 0x0080),
            ad=bool(raw & 0x0020),
            cd=bool(raw & 0x0010),
            rcode=raw & 0x000F,  # same mask as the CLI's getRCODE
        )

    def describe(self) -> str:
        names = ("QR", "AA", "TC", "RD", "RA", "AD", "CD")
        values = (self.qr, self.aa, self.tc, self.rd, self.ra, self.ad, self.cd)
        set_bits = [n for n, v in zip(names, values, strict=True) if v]
        return " ".join([f"0x{self.raw:04x}", *set_bits, f"RCODE={self.rcode_name}"])


@dataclass(frozen=True)
class Header:
    txid: int
    flags: Flags
    qdcount: int
    ancount: int
    nscount: int
    arcount: int


def parse_header(data: bytes) -> Header:
    if len(data) < HEADER_LEN:
        raise MalformedResponse(f"packet shorter than DNS header ({len(data)} < {HEADER_LEN} bytes)")
    txid, flags, qd, an, ns, ar = struct.unpack(HEADER_FMT, data[:HEADER_LEN])
    return Header(txid, Flags.from_raw(flags), qd, an, ns, ar)
```

- [ ] **Step 4: Run to verify pass, lint, commit**

`uv run pytest tests/test_protocol.py -v` → all PASS. `uv run ruff check . && uv run ruff format .`

```bash
git add dns-resolver-app/backend
git commit -m "feat(backend): parse DNS header and decode flags

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: `protocol.py` — `decode_name` with compression pointers

**Files:**
- Modify: `backend/app/dns/protocol.py` (append)
- Test: `backend/tests/test_protocol.py` (append)

**Interfaces:**
- Produces: `decode_name(data: bytes, offset: int) -> tuple[str, int]` — returns `(dotted_name_without_trailing_dot, offset_after_the_name_in_the_stream)`; root name is `""`; raises `MalformedResponse` on truncation, pointer loops, or label types `0x40–0xBF`. Constant `MAX_POINTER_JUMPS = 128`.

- [ ] **Step 1: Append the failing tests**

Add `decode_name` to the imports, then append:

```python
# --- name decoding with compression pointers ---------------------------------------------

# 12 zero header bytes, then "www.example.com" at offset 12..29
_HDR = b"\x00" * 12
_NAME = b"\x03www\x07example\x03com\x00"


def test_decode_name_plain():
    assert decode_name(_NAME, 0) == ("www.example.com", 17)


def test_decode_name_root():
    assert decode_name(b"\x00", 0) == ("", 1)


def test_decode_name_pointer_to_earlier_name():
    data = _HDR + _NAME + b"\xc0\x0c"  # pointer to offset 12
    assert decode_name(data, 29) == ("www.example.com", 31)


def test_decode_name_labels_then_pointer():
    # "mail" + pointer to "example.com" (offset 16 is the \x07example label)
    data = _HDR + _NAME + b"\x04mail\xc0\x10"
    assert decode_name(data, 29) == ("mail.example.com", 36)


@pytest.mark.parametrize(
    "data, offset",
    [
        (b"\xc0\x00", 0),  # points at itself
        (b"\xc0\x02\xc0\x00", 0),  # two pointers chasing each other
        (b"\xc0\x50", 0),  # points past the end
        (b"\x05ab", 0),  # label runs past the end
        (b"\xc0", 0),  # pointer byte without its second byte
        (b"\x40abc\x00", 0),  # reserved label type
        (b"\x03www", 4),  # offset past the end
    ],
)
def test_decode_name_rejects_malformed(data, offset):
    with pytest.raises(MalformedResponse):
        decode_name(data, offset)
```

- [ ] **Step 2: Run to verify failure**

`uv run pytest tests/test_protocol.py -k decode_name -v` — expected: ImportError for `decode_name`.

- [ ] **Step 3: Append the implementation**

```python
# --- name decoding -----------------------------------------------------------------------

MAX_POINTER_JUMPS = 128


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read a domain name starting at ``offset``, following RFC 1035 §4.1.4 pointers.

    Returns (name, next_offset). ``next_offset`` is where the field *in the stream* ends:
    after the zero byte for an inline name, or after the first 2-byte pointer.
    """
    labels: list[str] = []
    pos = offset
    next_offset: int | None = None
    jumps = 0
    while True:
        if pos >= len(data):
            raise MalformedResponse(f"name at offset {offset} runs past end of packet")
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length >= 0xC0:  # top two bits 11 -> pointer
            if pos + 1 >= len(data):
                raise MalformedResponse(f"truncated compression pointer at offset {pos}")
            if next_offset is None:
                next_offset = pos + 2
            jumps += 1
            if jumps > MAX_POINTER_JUMPS:
                raise MalformedResponse("compression pointer loop")
            pos = ((length & 0x3F) << 8) | data[pos + 1]
            continue
        if length >= 0x40:
            raise MalformedResponse(f"unsupported label type 0x{length:02x} at offset {pos}")
        start, end = pos + 1, pos + 1 + length
        if end > len(data):
            raise MalformedResponse(f"label at offset {pos} runs past end of packet")
        labels.append(data[start:end].decode("ascii", errors="replace"))
        pos = end
    return ".".join(labels), (next_offset if next_offset is not None else pos)
```

- [ ] **Step 4: Run to verify pass, lint, commit**

`uv run pytest tests/test_protocol.py -v` → all PASS. `uv run ruff check . && uv run ruff format .`

```bash
git add dns-resolver-app/backend
git commit -m "feat(backend): decode names with compression pointers

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 5: `protocol.py` — records, full response parsing, real packet fixtures

**Files:**
- Modify: `backend/app/dns/protocol.py` (append)
- Create: `backend/tests/fixtures/capture.py`, `backend/tests/fixtures/google_com_a.hex`, `backend/tests/fixtures/www_microsoft_com_cname.hex`, `backend/tests/fixtures/nxdomain_soa.hex`
- Test: `backend/tests/test_protocol.py` (append)

**Interfaces:**
- Consumes: `decode_name`, `parse_header`, `Span`, name tables from Tasks 2–4.
- Produces: `Question(name:str, qtype:int, qclass:int)`; `ResourceRecord(name:str, rtype:int, rclass:int, ttl:int, rdlength:int, rdata:bytes, data:str)`; `DnsMessage(header:Header, questions:tuple[Question,...], answers:tuple[ResourceRecord,...], authority:tuple[ResourceRecord,...], additional:tuple[ResourceRecord,...], spans:tuple[Span,...])`; `parse_record(data, offset, section, spans:list[Span]) -> tuple[ResourceRecord, int]`; `parse_response(data: bytes) -> DnsMessage`.

- [ ] **Step 1: Write the capture script and capture the fixtures (real network, run once)**

`backend/tests/fixtures/capture.py`:

```python
"""Capture real DNS responses as hex fixtures. Run from backend/: uv run python tests/fixtures/capture.py"""

import pathlib
import socket
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from app.dns.protocol import QTYPE_A, build_query  # noqa: E402

HERE = pathlib.Path(__file__).parent
SERVER = ("8.8.8.8", 53)
TXID = 0x1234
CASES = {
    "google_com_a.hex": "google.com",
    "www_microsoft_com_cname.hex": "www.microsoft.com",
    "nxdomain_soa.hex": "this-domain-does-not-exist-xyz123.com",
}

for filename, domain in CASES.items():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(build_query(TXID, domain, QTYPE_A), SERVER)
        response, _ = sock.recvfrom(4096)
    (HERE / filename).write_text(response.hex() + "\n", encoding="ascii")
    print(f"{filename}: {len(response)} bytes for {domain}")
```

Run from `backend/`: `uv run python tests/fixtures/capture.py` — expected: three lines, each > 40 bytes. Check `www_microsoft_com_cname.hex` starts with `12348180` (txid echoed, QR RD RA) and `nxdomain_soa.hex` starts with `12348183` (rcode 3).

- [ ] **Step 2: Append the failing tests**

Add `QTYPE_CNAME, QTYPE_SOA, parse_response` to the imports and `import ipaddress` at the top, then append:

```python
# --- full response parsing on captured packets -------------------------------------------


def _assert_spans_contiguous(spans, length):
    ordered = sorted(spans, key=lambda s: s.start)
    assert ordered[0].start == 0
    for prev, nxt in zip(ordered, ordered[1:], strict=False):
        assert prev.end == nxt.start, f"gap/overlap between {prev} and {nxt}"
    assert ordered[-1].end == length


def test_parse_google_a_records(load_fixture):
    data = load_fixture("google_com_a.hex")
    msg = parse_response(data)
    assert msg.header.txid == 0x1234
    assert msg.header.flags.qr and msg.header.flags.rcode == 0
    assert msg.questions[0].name == "google.com" and msg.questions[0].qtype == QTYPE_A
    assert len(msg.answers) == msg.header.ancount >= 1
    for rr in msg.answers:
        assert rr.rtype == QTYPE_A and rr.rdlength == 4
        ipaddress.IPv4Address(rr.data)  # raises if not a dotted quad
    _assert_spans_contiguous(msg.spans, len(data))


def test_parse_cname_chain_walks_by_rdlength(load_fixture):
    """The CLI's fixed-16-byte loop produced garbage here; RDLENGTH-based walking must not."""
    data = load_fixture("www_microsoft_com_cname.hex")
    msg = parse_response(data)
    assert len(msg.answers) == msg.header.ancount >= 2
    assert msg.answers[0].rtype == QTYPE_CNAME
    assert msg.answers[0].name == "www.microsoft.com"
    assert "." in msg.answers[0].data and not msg.answers[0].data.endswith(".")
    assert msg.answers[-1].rtype == QTYPE_A
    ipaddress.IPv4Address(msg.answers[-1].data)
    _assert_spans_contiguous(msg.spans, len(data))
    name_span = next(s for s in msg.spans if s.section == "answer" and s.field == "NAME")
    assert name_span.value.startswith("→ 0x0c (")


def test_parse_nxdomain_puts_soa_in_authority_not_answers(load_fixture):
    msg = parse_response(load_fixture("nxdomain_soa.hex"))
    assert msg.header.flags.rcode_name == "NXDOMAIN"
    assert msg.answers == ()
    assert len(msg.authority) == msg.header.nscount == 1
    soa = msg.authority[0]
    assert soa.rtype == QTYPE_SOA
    assert len(soa.data.split()) == 7  # mname rname serial refresh retry expire minimum


def test_parse_rejects_truncated_packet(load_fixture):
    with pytest.raises(MalformedResponse):
        parse_response(load_fixture("google_com_a.hex")[:20])


def test_parse_rejects_bad_a_rdlength():
    header = bytes.fromhex("0001 8180 0001 0001 0000 0000")
    question = b"\x01a\x00" + b"\x00\x01\x00\x01"
    bad_answer = (
        b"\xc0\x0c" + b"\x00\x01\x00\x01" + b"\x00\x00\x00\x3c" + b"\x00\x05" + b"\x01\x02\x03\x04\x05"
    )
    with pytest.raises(MalformedResponse):
        parse_response(header + question + bad_answer)


def test_parse_marks_trailing_bytes():
    header = bytes.fromhex("0001 8180 0001 0000 0000 0000")
    question = b"\x01a\x00" + b"\x00\x01\x00\x01"
    msg = parse_response(header + question + b"\xde\xad")
    assert msg.spans[-1].section == "trailing" and msg.spans[-1].value == "2 bytes"
```

- [ ] **Step 3: Run to verify failure**

`uv run pytest tests/test_protocol.py -k parse -v` — expected: ImportError for `parse_response`.

- [ ] **Step 4: Append the implementation**

Add `import ipaddress` to the imports at the top of `protocol.py`, then append:

```python
# --- records and full messages ------------------------------------------------------------


@dataclass(frozen=True)
class Question:
    name: str
    qtype: int
    qclass: int


@dataclass(frozen=True)
class ResourceRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdlength: int
    rdata: bytes
    data: str  # human-readable RDATA: dotted IPv4, IPv6, a name, SOA fields, or hex


@dataclass(frozen=True)
class DnsMessage:
    header: Header
    questions: tuple[Question, ...]
    answers: tuple[ResourceRecord, ...]
    authority: tuple[ResourceRecord, ...]
    additional: tuple[ResourceRecord, ...]
    spans: tuple[Span, ...]


def _decode_rdata(data: bytes, rdata_offset: int, rtype: int, rdlength: int) -> str:
    rdata = data[rdata_offset : rdata_offset + rdlength]
    if rtype == QTYPE_A:
        if rdlength != 4:
            raise MalformedResponse(f"A record RDLENGTH must be 4, got {rdlength}")
        return ".".join(str(octet) for octet in struct.unpack("!BBBB", rdata))  # as the CLI
    if rtype == QTYPE_AAAA:
        if rdlength != 16:
            raise MalformedResponse(f"AAAA record RDLENGTH must be 16, got {rdlength}")
        return ipaddress.IPv6Address(rdata).compressed
    if rtype in (QTYPE_CNAME, QTYPE_NS, QTYPE_PTR):
        # RDATA is a name whose pointers may reference anywhere in the packet
        name, _ = decode_name(data, rdata_offset)
        return name
    if rtype == QTYPE_SOA:
        mname, pos = decode_name(data, rdata_offset)
        rname, pos = decode_name(data, pos)
        if pos + 20 > len(data):
            raise MalformedResponse("SOA record truncated")
        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", data[pos : pos + 20])
        return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
    return rdata.hex(" ")


def parse_record(
    data: bytes, offset: int, section: str, spans: list[Span]
) -> tuple[ResourceRecord, int]:
    """Parse one RR at ``offset``; append its field spans; return (record, offset after RDATA)."""
    name, pos = decode_name(data, offset)
    name_value = name or "<root>"
    if data[offset] >= 0xC0:
        target = ((data[offset] & 0x3F) << 8) | data[offset + 1]
        name_value = f"→ 0x{target:02x} ({name})"
    spans.append(Span(section, "NAME", offset, pos, name_value))
    if pos + 10 > len(data):
        raise MalformedResponse(f"record at offset {offset} truncated before RDATA")
    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[pos : pos + 10])
    spans.append(Span(section, "TYPE", pos, pos + 2, rtype_name(rtype)))
    spans.append(Span(section, "CLASS", pos + 2, pos + 4, rclass_name(rclass)))
    spans.append(Span(section, "TTL", pos + 4, pos + 8, f"{ttl}s"))
    spans.append(Span(section, "RDLENGTH", pos + 8, pos + 10, str(rdlength)))
    rdata_offset = pos + 10
    end = rdata_offset + rdlength  # the CNAME fix: advance by RDLENGTH, not a fixed 16
    if end > len(data):
        raise MalformedResponse(f"RDATA at offset {rdata_offset} runs past end of packet")
    decoded = _decode_rdata(data, rdata_offset, rtype, rdlength)
    spans.append(Span(section, "RDATA", rdata_offset, end, decoded))
    record = ResourceRecord(name, rtype, rclass, ttl, rdlength, data[rdata_offset:end], decoded)
    return record, end


def parse_response(data: bytes) -> DnsMessage:
    header = parse_header(data)
    spans: list[Span] = [
        Span("header", "ID", 0, 2, f"0x{header.txid:04x}"),
        Span("header", "FLAGS", 2, 4, header.flags.describe()),
        Span("header", "QDCOUNT", 4, 6, str(header.qdcount)),
        Span("header", "ANCOUNT", 6, 8, str(header.ancount)),
        Span("header", "NSCOUNT", 8, 10, str(header.nscount)),
        Span("header", "ARCOUNT", 10, 12, str(header.arcount)),
    ]
    pos = HEADER_LEN

    questions: list[Question] = []
    for _ in range(header.qdcount):
        name, name_end = decode_name(data, pos)
        spans.append(Span("question", "QNAME", pos, name_end, name))
        if name_end + 4 > len(data):
            raise MalformedResponse("question section truncated")
        qtype, qclass = struct.unpack("!HH", data[name_end : name_end + 4])
        spans.append(Span("question", "QTYPE", name_end, name_end + 2, rtype_name(qtype)))
        spans.append(Span("question", "QCLASS", name_end + 2, name_end + 4, rclass_name(qclass)))
        questions.append(Question(name, qtype, qclass))
        pos = name_end + 4

    sections: dict[str, tuple[ResourceRecord, ...]] = {}
    for section, count in (
        ("answer", header.ancount),
        ("authority", header.nscount),
        ("additional", header.arcount),
    ):
        records: list[ResourceRecord] = []
        for _ in range(count):  # exactly the header's count — no more (the ANCOUNT fix)
            record, pos = parse_record(data, pos, section, spans)
            records.append(record)
        sections[section] = tuple(records)

    if pos < len(data):
        spans.append(Span("trailing", "unparsed", pos, len(data), f"{len(data) - pos} bytes"))

    return DnsMessage(
        header=header,
        questions=tuple(questions),
        answers=sections["answer"],
        authority=sections["authority"],
        additional=sections["additional"],
        spans=tuple(spans),
    )
```

- [ ] **Step 5: Run to verify pass, lint, commit**

`uv run pytest -v` → all PASS. `uv run ruff check . && uv run ruff format .`

```bash
git add dns-resolver-app/backend
git commit -m "feat(backend): parse full DNS responses by RDLENGTH with captured fixtures

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 6: `transport.py` — UDP exchange with deadline, RTT, and error mapping

**Files:**
- Create: `backend/app/dns/transport.py`
- Test: `backend/tests/test_transport.py`, `backend/tests/fake_dns_server.py`

**Interfaces:**
- Consumes: `QueryTimeout`, `NetworkError` (Task 1); `build_query` (Task 2, tests only).
- Produces: `Exchange(request: bytes, response: bytes, server: str, port: int, rtt_ms: float)`; `send_query(request: bytes, server: str, port: int, timeout: float, expected_txid: int) -> Exchange`; constant `RECV_BUFFER = 4096`. Test helper `FakeDnsServer(reply: Callable[[bytes], list[bytes]])` context manager with `.port`.

- [ ] **Step 1: Write the fake server helper `backend/tests/fake_dns_server.py`**

```python
"""A tiny UDP server for transport tests. ``reply(request)`` returns the datagrams to send back."""

from __future__ import annotations

import socket
import threading
from collections.abc import Callable


class FakeDnsServer:
    def __init__(self, reply: Callable[[bytes], list[bytes]]) -> None:
        self.reply = reply
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.05)
        self.port: int = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> FakeDnsServer:
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                request, addr = self.sock.recvfrom(4096)
            except TimeoutError:
                continue
            for datagram in self.reply(request):
                self.sock.sendto(datagram, addr)


def echo_response(request: bytes) -> list[bytes]:
    """A minimal valid response: same ID, flags QR|RD|RA, the question echoed, no records."""
    return [request[:2] + b"\x81\x80" + request[4:]]
```

- [ ] **Step 2: Write the failing tests `backend/tests/test_transport.py`**

```python
import socket
import time

import pytest

from app.dns.errors import NetworkError, QueryTimeout
from app.dns.protocol import build_query
from app.dns.transport import Exchange, send_query
from tests.fake_dns_server import FakeDnsServer, echo_response

REQUEST = build_query(0x1234, "example.com")


def test_happy_path_returns_exchange_with_rtt():
    with FakeDnsServer(echo_response) as server:
        exchange = send_query(REQUEST, "127.0.0.1", server.port, 2.0, 0x1234)
    assert isinstance(exchange, Exchange)
    assert exchange.request == REQUEST
    assert exchange.response[:2] == b"\x12\x34"
    assert exchange.server == "127.0.0.1" and exchange.port == server.port
    assert exchange.rtt_ms > 0


def test_datagram_with_wrong_txid_is_discarded():
    def reply(request: bytes) -> list[bytes]:
        stale = b"\xff\xff" + request[2:]
        return echo_response(stale) + echo_response(request)

    with FakeDnsServer(reply) as server:
        exchange = send_query(REQUEST, "127.0.0.1", server.port, 2.0, 0x1234)
    assert exchange.response[:2] == b"\x12\x34"


def test_silence_raises_query_timeout_near_the_deadline():
    with FakeDnsServer(lambda _request: []) as server:
        started = time.monotonic()
        with pytest.raises(QueryTimeout) as info:
            send_query(REQUEST, "127.0.0.1", server.port, 0.5, 0x1234)
    assert 0.4 < time.monotonic() - started < 1.5
    assert str(info.value) == f"No response from 127.0.0.1:{server.port} within 0.5s"


def test_wrong_txid_only_still_times_out():
    """Discarded datagrams must not reset the deadline."""

    def reply(request: bytes) -> list[bytes]:
        return echo_response(b"\xff\xff" + request[2:])

    with FakeDnsServer(reply) as server:
        with pytest.raises(QueryTimeout):
            send_query(REQUEST, "127.0.0.1", server.port, 0.3, 0x1234)


def test_os_error_maps_to_network_error(monkeypatch):
    def broken_socket(*args, **kwargs):
        raise OSError(10051, "A socket operation was attempted to an unreachable network")

    monkeypatch.setattr(socket, "socket", broken_socket)
    with pytest.raises(NetworkError):
        send_query(REQUEST, "127.0.0.1", 53, 1.0, 0x1234)


@pytest.mark.network
def test_real_public_resolver_answers():
    exchange = send_query(REQUEST, "8.8.8.8", 53, 5.0, 0x1234)
    assert exchange.response[:2] == b"4" and exchange.rtt_ms > 0
```

- [ ] **Step 3: Run to verify failure**

`uv run pytest tests/test_transport.py -v` — expected: ImportError for `app.dns.transport`.

- [ ] **Step 4: Write `backend/app/dns/transport.py`**

```python
"""UDP transport — the CLI's ``handleQuery`` with a deadline loop, RTT, and typed errors."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from app.dns.errors import NetworkError, QueryTimeout

RECV_BUFFER = 4096  # classic DNS/UDP is <= 512 bytes; a larger buffer never truncates


@dataclass(frozen=True)
class Exchange:
    request: bytes
    response: bytes
    server: str
    port: int
    rtt_ms: float


def send_query(
    request: bytes, server: str, port: int, timeout: float, expected_txid: int
) -> Exchange:
    """Send ``request`` over UDP and wait for the matching response.

    Datagrams from another address or with a different transaction ID are discarded
    (stale replies to an earlier timed-out query, or spoofed packets) and waiting
    continues until the deadline.
    """
    deadline = time.monotonic() + timeout
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            started = time.perf_counter()
            sock.sendto(request, (server, port))
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise QueryTimeout(server, port, timeout)
                sock.settimeout(remaining)
                response, addr = sock.recvfrom(RECV_BUFFER)
                if addr[0] != server or addr[1] != port:
                    continue
                if len(response) < 2 or int.from_bytes(response[:2], "big") != expected_txid:
                    continue
                rtt_ms = (time.perf_counter() - started) * 1000.0
                return Exchange(request, response, server, port, rtt_ms)
    except TimeoutError:  # socket.timeout is an alias; must precede OSError
        raise QueryTimeout(server, port, timeout) from None
    except OSError as exc:  # ConnectionResetError (ICMP port unreachable on Windows), gaierror, ...
        raise NetworkError(str(exc)) from exc
```

- [ ] **Step 5: Run to verify pass, lint, commit**

`uv run pytest tests/test_transport.py -v` → 5 PASS, 1 skipped (add `--run-network` to run the last one). `uv run ruff check . && uv run ruff format .`

```bash
git add dns-resolver-app/backend
git commit -m "feat(backend): UDP transport with deadline loop, RTT and typed errors

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 7: `cache.py` — TTL cache

**Files:**
- Create: `backend/app/dns/cache.py`
- Test: `backend/tests/test_cache.py`

**Interfaces:**
- Consumes: `DnsMessage`, `ResourceRecord`, `parse_response` (Task 5); `Exchange` (Task 6).
- Produces: `CacheKey = tuple[str, int]`; `CacheHit(message: DnsMessage, exchange: Exchange, ttl_remaining: int, age: int)`; `TtlCache(max_entries: int = 1000, clock: Callable[[], float] = time.monotonic)` with `get(key) -> CacheHit | None`, `put(key, message, exchange) -> None`, `clear() -> None`, `__len__`.

- [ ] **Step 1: Write the failing tests `backend/tests/test_cache.py`**

```python
import struct

from app.dns.cache import TtlCache
from app.dns.protocol import parse_response
from app.dns.transport import Exchange

EXCHANGE = Exchange(request=b"", response=b"", server="8.8.8.8", port=53, rtt_ms=1.0)
KEY = ("example.com", 1)


def make_message(rcode: int = 0, ttls: tuple[int, ...] = (300,)):
    """A synthetic response for example.com with one A record per TTL given."""
    header = struct.pack("!HHHHHH", 1, 0x8180 | rcode, 1, len(ttls), 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    answers = b"".join(
        b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + bytes([93, 184, 216, 34]) for ttl in ttls
    )
    return parse_response(header + question + answers)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_miss_then_hit_with_remaining_ttl():
    clock = FakeClock()
    cache = TtlCache(clock=clock)
    assert cache.get(KEY) is None
    cache.put(KEY, make_message(ttls=(300, 60)), EXCHANGE)
    clock.advance(10)
    hit = cache.get(KEY)
    assert hit is not None
    assert hit.age == 10 and hit.ttl_remaining == 50  # min TTL governs expiry
    assert [rr.ttl for rr in hit.message.answers] == [290, 50]
    assert hit.exchange is EXCHANGE


def test_entry_expires_at_min_ttl():
    clock = FakeClock()
    cache = TtlCache(clock=clock)
    cache.put(KEY, make_message(ttls=(300, 60)), EXCHANGE)
    clock.advance(60)
    assert cache.get(KEY) is None
    assert len(cache) == 0


def test_error_responses_and_empty_answers_are_not_cached():
    cache = TtlCache(clock=FakeClock())
    cache.put(KEY, make_message(rcode=3, ttls=()), EXCHANGE)
    cache.put(("other.com", 1), make_message(rcode=0, ttls=()), EXCHANGE)
    assert len(cache) == 0


def test_zero_ttl_is_not_cached():
    cache = TtlCache(clock=FakeClock())
    cache.put(KEY, make_message(ttls=(0,)), EXCHANGE)
    assert cache.get(KEY) is None


def test_capacity_evicts_expired_first_then_oldest():
    clock = FakeClock()
    cache = TtlCache(max_entries=2, clock=clock)
    cache.put(("a.com", 1), make_message(ttls=(5,)), EXCHANGE)
    cache.put(("b.com", 1), make_message(ttls=(500,)), EXCHANGE)
    clock.advance(10)  # a.com expired
    cache.put(("c.com", 1), make_message(ttls=(500,)), EXCHANGE)
    assert cache.get(("a.com", 1)) is None and cache.get(("b.com", 1)) is not None
    cache.put(("d.com", 1), make_message(ttls=(500,)), EXCHANGE)  # full: oldest (b) goes
    assert cache.get(("b.com", 1)) is None
    assert cache.get(("c.com", 1)) is not None and cache.get(("d.com", 1)) is not None


def test_put_replaces_and_clear_empties():
    clock = FakeClock()
    cache = TtlCache(clock=clock)
    cache.put(KEY, make_message(ttls=(10,)), EXCHANGE)
    cache.put(KEY, make_message(ttls=(100,)), EXCHANGE)
    clock.advance(50)
    assert cache.get(KEY) is not None
    cache.clear()
    assert len(cache) == 0 and cache.get(KEY) is None
```

- [ ] **Step 2: Run to verify failure**

`uv run pytest tests/test_cache.py -v` — expected: ImportError for `app.dns.cache`.

- [ ] **Step 3: Write `backend/app/dns/cache.py`**

```python
"""In-process TTL cache keyed by (domain, qtype), behaving like a caching stub resolver."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, replace

from app.dns.protocol import DnsMessage, ResourceRecord
from app.dns.transport import Exchange

CacheKey = tuple[str, int]


@dataclass(frozen=True)
class CacheHit:
    message: DnsMessage  # TTLs already decremented by ``age``
    exchange: Exchange  # the original wire exchange (for the hex dump)
    ttl_remaining: int
    age: int


@dataclass
class _Entry:
    message: DnsMessage
    exchange: Exchange
    stored_at: float
    expires_at: float


class TtlCache:
    def __init__(
        self, max_entries: int = 1000, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._max_entries = max_entries
        self._clock = clock
        self._entries: OrderedDict[CacheKey, _Entry] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: CacheKey) -> CacheHit | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            now = self._clock()
            if now >= entry.expires_at:
                del self._entries[key]
                return None
            age = int(now - entry.stored_at)
            return CacheHit(
                message=_aged(entry.message, age),
                exchange=entry.exchange,
                ttl_remaining=int(entry.expires_at - now),
                age=age,
            )

    def put(self, key: CacheKey, message: DnsMessage, exchange: Exchange) -> None:
        if message.header.flags.rcode != 0 or not message.answers:
            return  # no negative caching; nothing to cache without answers
        ttl = min(rr.ttl for rr in message.answers)
        if ttl <= 0:
            return
        with self._lock:
            now = self._clock()
            self._entries.pop(key, None)
            if len(self._entries) >= self._max_entries:
                self._evict_locked(now)
            self._entries[key] = _Entry(message, exchange, now, now + ttl)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def _evict_locked(self, now: float) -> None:
        for key in [k for k, e in self._entries.items() if now >= e.expires_at]:
            del self._entries[key]
        while len(self._entries) >= self._max_entries:
            self._entries.popitem(last=False)  # oldest insertion


def _aged(message: DnsMessage, age: int) -> DnsMessage:
    def aged(records: tuple[ResourceRecord, ...]) -> tuple[ResourceRecord, ...]:
        return tuple(replace(rr, ttl=max(0, rr.ttl - age)) for rr in records)

    return replace(
        message,
        answers=aged(message.answers),
        authority=aged(message.authority),
        additional=aged(message.additional),
    )
```

- [ ] **Step 4: Run to verify pass, lint, commit**

`uv run pytest tests/test_cache.py -v` → 6 PASS. `uv run ruff check . && uv run ruff format .`

```bash
git add dns-resolver-app/backend
git commit -m "feat(backend): TTL cache with aging and bounded size

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 8: `config.py` and `schemas.py` — settings, request validation, response models

**Files:**
- Create: `backend/app/config.py`, `backend/app/schemas.py`
- Test: `backend/tests/test_schemas.py`

**Interfaces:**
- Produces: `Settings` (env prefix `DNS_`: `default_timeout: float = 5.0`, `cache_max_entries: int = 1000`, `cors_origins: list[str] = []`, `log_level: str = "INFO"`) and `get_settings() -> Settings` (cached); `normalise_domain(raw: str) -> str`; Pydantic models `ResolveRequest(domain, server, qtype: Literal["A","AAAA"]="A", timeout: float, bypass_cache: bool=False)`, `FlagsOut`, `HeaderOut`, `QuestionOut`, `RecordOut`, `QueryOut`, `TimingOut`, `CacheOut`, `SpanOut`, `PacketOut`, `PacketsOut`, `ResolveResponse`, `ErrorResponse(error, detail)`, `HealthOut(status, cache_entries)`. `QuestionOut`/`RecordOut` expose the class as field `rr_class` serialised under alias `class`.

- [ ] **Step 1: Write the failing tests `backend/tests/test_schemas.py`**

```python
import pytest
from pydantic import ValidationError

from app.schemas import QuestionOut, ResolveRequest, normalise_domain


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("www.example.com", "www.example.com"),
        ("  WWW.Example.COM.  ", "www.example.com"),  # whitespace, case, trailing dot
        ("bücher.example", "xn--bcher-kva.example"),  # IDNA → punycode
        ("a" * 63 + ".com", "a" * 63 + ".com"),
    ],
)
def test_normalise_domain_accepts(raw, expected):
    assert normalise_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", "   ", ".", "a..b", "-bad.com", "bad-.com", "a" * 64 + ".com", "under_score.com",
     "x." * 127 + "com", "sp ace.com"],
)
def test_normalise_domain_rejects(raw):
    with pytest.raises(ValueError):
        normalise_domain(raw)


def test_resolve_request_defaults_and_normalisation():
    req = ResolveRequest(domain="Example.COM.", server=" 8.8.8.8 ")
    assert req.domain == "example.com" and req.server == "8.8.8.8"
    assert req.qtype == "A" and req.timeout == 5.0 and req.bypass_cache is False


@pytest.mark.parametrize(
    "field, value, fragment",
    [
        ("server", "not-an-ip", "IPv4"),
        ("server", "2001:db8::1", "IPv4"),
        ("server", "8.8.8.8:53", "IPv4"),
        ("qtype", "MX", "'A' or 'AAAA'"),
        ("timeout", 0.1, "0.5"),
        ("timeout", 99, "10"),
        ("domain", "a..b", "empty label"),
    ],
)
def test_resolve_request_rejects(field, value, fragment):
    payload = {"domain": "example.com", "server": "8.8.8.8", field: value}
    with pytest.raises(ValidationError) as info:
        ResolveRequest(**payload)
    assert fragment in str(info.value)


def test_class_field_serialises_under_alias():
    out = QuestionOut(name="a.com", type="A", rr_class="IN")
    assert out.model_dump(by_alias=True) == {"name": "a.com", "type": "A", "class": "IN"}
```

- [ ] **Step 2: Run to verify failure**

`uv run pytest tests/test_schemas.py -v` — expected: ImportError for `app.schemas`.

- [ ] **Step 3: Write `backend/app/config.py`**

```python
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings, overridable with DNS_* environment variables."""

    model_config = SettingsConfigDict(env_prefix="DNS_")

    default_timeout: float = 5.0
    cache_max_entries: int = 1000
    cors_origins: list[str] = []  # empty → CORS middleware not installed (frontend proxies)
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()
```

- [ ] **Step 4: Write `backend/app/schemas.py`**

```python
"""Pydantic models for the HTTP API: request validation and the response shape."""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.config import get_settings

LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
MAX_LABEL_LEN = 63
MAX_DOMAIN_LEN = 253


def normalise_domain(raw: str) -> str:
    """Trim, drop one trailing dot, lower-case, IDNA-encode, then enforce RFC 1035 label rules."""
    name = raw.strip().removesuffix(".").lower()
    if not name:
        raise ValueError("domain must not be empty")
    if any(not label for label in name.split(".")):
        raise ValueError("domain contains an empty label (consecutive or leading dots)")
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"domain is not a valid internationalised name ({exc})") from None
    if len(name) > MAX_DOMAIN_LEN:
        raise ValueError(f"domain longer than {MAX_DOMAIN_LEN} characters")
    for label in name.split("."):
        if len(label) > MAX_LABEL_LEN:
            raise ValueError(f"label {label[:10]!r}… longer than {MAX_LABEL_LEN} characters")
        if not LABEL_RE.match(label):
            raise ValueError(
                f"invalid label {label!r}: use letters, digits and hyphens (not at the ends)"
            )
    return name


# --- request -----------------------------------------------------------------------------


class ResolveRequest(BaseModel):
    domain: str = Field(examples=["www.example.com"])
    server: str = Field(examples=["8.8.8.8"], description="IPv4 address of the DNS server")
    qtype: Literal["A", "AAAA"] = "A"
    timeout: float = Field(
        default_factory=lambda: get_settings().default_timeout, ge=0.5, le=10.0
    )
    bypass_cache: bool = False

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, value: str) -> str:
        return normalise_domain(value)

    @field_validator("server")
    @classmethod
    def _validate_server(cls, value: str) -> str:
        try:
            return str(ipaddress.IPv4Address(value.strip()))
        except ValueError:
            raise ValueError("server must be an IPv4 address, e.g. 8.8.8.8") from None


# --- response ----------------------------------------------------------------------------


class FlagsOut(BaseModel):
    raw: int
    qr: bool
    opcode: int
    aa: bool
    tc: bool
    rd: bool
    ra: bool
    ad: bool
    cd: bool
    rcode: int
    rcode_name: str


class HeaderOut(BaseModel):
    transaction_id: int
    flags: FlagsOut
    qdcount: int
    ancount: int
    nscount: int
    arcount: int


class QuestionOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    type: str
    rr_class: str = Field(serialization_alias="class")


class RecordOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    type: str
    type_code: int
    rr_class: str = Field(serialization_alias="class")
    ttl: int
    rdlength: int
    data: str


class QueryOut(BaseModel):
    domain: str
    qtype: str
    server: str
    port: int
    transaction_id: int


class TimingOut(BaseModel):
    rtt_ms: float | None  # None when served from cache


class CacheOut(BaseModel):
    status: Literal["HIT", "MISS", "BYPASS"]
    ttl_remaining: int | None


class SpanOut(BaseModel):
    section: str
    field: str
    start: int
    end: int
    value: str


class PacketOut(BaseModel):
    hex: str  # lower-case, no separators
    spans: list[SpanOut]


class PacketsOut(BaseModel):
    query: PacketOut
    response: PacketOut


class ResolveResponse(BaseModel):
    query: QueryOut
    header: HeaderOut
    question: QuestionOut | None
    answers: list[RecordOut]
    authority: list[RecordOut]
    additional: list[RecordOut]
    resolved_ips: list[str]
    timing: TimingOut
    cache: CacheOut
    packets: PacketsOut


class ErrorResponse(BaseModel):
    error: str
    detail: str


class HealthOut(BaseModel):
    status: str
    cache_entries: int
```

- [ ] **Step 5: Run to verify pass, lint, commit**

`uv run pytest tests/test_schemas.py -v` → all PASS. `uv run ruff check . && uv run ruff format .`

```bash
git add dns-resolver-app/backend
git commit -m "feat(backend): settings and API schemas with domain/server validation

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 9: `service.py` — orchestration (cache → transport → parse → response model)

**Files:**
- Create: `backend/app/service.py`
- Test: `backend/tests/test_service.py`, `backend/tests/fakes.py`

**Interfaces:**
- Consumes: everything from Tasks 2–8.
- Produces: `DNS_PORT = 53`; `QTYPE_CODES = {"A": 1, "AAAA": 28}`; `resolve(req: ResolveRequest, cache: TtlCache) -> ResolveResponse`; `build_response(req, message, exchange, *, cache_status, ttl_remaining, rtt_ms) -> ResolveResponse`. Test helper `fake_send(load_fixture, name) -> Callable` that mimics `send_query` by returning the fixture with the expected txid patched in.

- [ ] **Step 1: Write the shared test fake `backend/tests/fakes.py`**

```python
"""Stand-ins for the network layer used by service and API tests."""

from __future__ import annotations

from collections.abc import Callable

from app.dns.transport import Exchange


def fake_send(load_fixture: Callable[[str], bytes], name: str, rtt_ms: float = 12.5):
    """Return a send_query look-alike that answers with a captured packet, txid patched to match."""

    def _send(request: bytes, server: str, port: int, timeout: float, expected_txid: int) -> Exchange:
        data = load_fixture(name)
        response = expected_txid.to_bytes(2, "big") + data[2:]
        return Exchange(request, response, server, port, rtt_ms)

    return _send


def raising_send(exc: Exception):
    def _send(*args, **kwargs):
        raise exc

    return _send
```

- [ ] **Step 2: Write the failing tests `backend/tests/test_service.py`**

```python
import pytest

from app import service
from app.dns.cache import TtlCache
from app.dns.errors import MalformedResponse
from app.dns.transport import Exchange
from app.schemas import ResolveRequest
from tests.fakes import fake_send

REQ = ResolveRequest(domain="www.microsoft.com", server="8.8.8.8")


def test_miss_then_hit(monkeypatch, load_fixture):
    monkeypatch.setattr(service, "send_query", fake_send(load_fixture, "www_microsoft_com_cname.hex"))
    cache = TtlCache()

    first = service.resolve(REQ, cache)
    assert first.cache.status == "MISS" and first.cache.ttl_remaining is None
    assert first.timing.rtt_ms == 12.5
    assert first.header.flags.rcode_name == "NOERROR"
    assert first.answers[0].type == "CNAME" and first.answers[-1].type == "A"
    assert first.resolved_ips == [rr.data for rr in first.answers if rr.type == "A"]
    assert first.question is not None and first.question.name == "www.microsoft.com"
    assert first.packets.query.hex.startswith(f"{first.header.transaction_id:04x}0100")
    assert first.packets.response.hex[:4] == f"{first.header.transaction_id:04x}"
    assert first.packets.response.spans[-1].end == len(first.packets.response.hex) // 2

    second = service.resolve(REQ, cache)
    assert second.cache.status == "HIT"
    assert second.cache.ttl_remaining is not None and second.cache.ttl_remaining > 0
    assert second.timing.rtt_ms is None
    assert second.header.transaction_id == first.header.transaction_id  # served from the stored exchange


def test_bypass_skips_lookup_but_refreshes(monkeypatch, load_fixture):
    monkeypatch.setattr(service, "send_query", fake_send(load_fixture, "google_com_a.hex"))
    cache = TtlCache()
    req = ResolveRequest(domain="google.com", server="8.8.8.8")
    service.resolve(req, cache)
    bypass = service.resolve(req.model_copy(update={"bypass_cache": True}), cache)
    assert bypass.cache.status == "BYPASS" and bypass.timing.rtt_ms == 12.5
    assert service.resolve(req, cache).cache.status == "HIT"


def test_nxdomain_is_returned_as_200_data_and_not_cached(monkeypatch, load_fixture):
    monkeypatch.setattr(service, "send_query", fake_send(load_fixture, "nxdomain_soa.hex"))
    cache = TtlCache()
    req = ResolveRequest(domain="this-domain-does-not-exist-xyz123.com", server="8.8.8.8")
    out = service.resolve(req, cache)
    assert out.header.flags.rcode_name == "NXDOMAIN"
    assert out.answers == [] and out.resolved_ips == []
    assert out.authority[0].type == "SOA"
    assert service.resolve(req, cache).cache.status == "MISS"


def test_txid_mismatch_is_malformed(monkeypatch, load_fixture):
    def wrong_txid(request, server, port, timeout, expected_txid):
        data = load_fixture("google_com_a.hex")
        return Exchange(request, b"\x00\x00" + data[2:], server, port, 1.0)

    monkeypatch.setattr(service, "send_query", wrong_txid)
    with pytest.raises(MalformedResponse, match="transaction ID mismatch"):
        service.resolve(ResolveRequest(domain="google.com", server="8.8.8.8"), TtlCache())


def test_query_not_response_is_malformed(monkeypatch):
    def echo_query(request, server, port, timeout, expected_txid):
        return Exchange(request, request, server, port, 1.0)  # QR=0

    monkeypatch.setattr(service, "send_query", echo_query)
    with pytest.raises(MalformedResponse, match="QR"):
        service.resolve(ResolveRequest(domain="google.com", server="8.8.8.8"), TtlCache())


def test_uses_port_53_and_requested_timeout(monkeypatch, load_fixture):
    seen = {}

    def spy(request, server, port, timeout, expected_txid):
        seen.update(server=server, port=port, timeout=timeout)
        return fake_send(load_fixture, "google_com_a.hex")(request, server, port, timeout, expected_txid)

    monkeypatch.setattr(service, "send_query", spy)
    service.resolve(ResolveRequest(domain="google.com", server="1.1.1.1", timeout=2.5), TtlCache())
    assert seen == {"server": "1.1.1.1", "port": 53, "timeout": 2.5}
```

- [ ] **Step 3: Run to verify failure**

`uv run pytest tests/test_service.py -v` — expected: ImportError for `app.service`.

- [ ] **Step 4: Write `backend/app/service.py`**

```python
"""Resolve a request: consult the cache, otherwise build → send → parse → validate → cache."""

from __future__ import annotations

import secrets
from dataclasses import asdict

from app.dns.cache import TtlCache
from app.dns.errors import MalformedResponse
from app.dns.protocol import (
    QTYPE_A,
    QTYPE_AAAA,
    DnsMessage,
    ResourceRecord,
    Span,
    build_query,
    build_query_spans,
    parse_response,
    rclass_name,
    rtype_name,
)
from app.dns.transport import Exchange, send_query
from app.schemas import (
    CacheOut,
    FlagsOut,
    HeaderOut,
    PacketOut,
    PacketsOut,
    QueryOut,
    QuestionOut,
    RecordOut,
    ResolveRequest,
    ResolveResponse,
    SpanOut,
    TimingOut,
)

DNS_PORT = 53  # the standard DNS port, fixed by the assignment brief
QTYPE_CODES = {"A": QTYPE_A, "AAAA": QTYPE_AAAA}


def resolve(req: ResolveRequest, cache: TtlCache) -> ResolveResponse:
    qtype = QTYPE_CODES[req.qtype]
    key = (req.domain, qtype)

    if not req.bypass_cache:
        hit = cache.get(key)
        if hit is not None:
            return build_response(
                req, hit.message, hit.exchange,
                cache_status="HIT", ttl_remaining=hit.ttl_remaining, rtt_ms=None,
            )

    txid = secrets.randbelow(65536)  # unpredictable IDs make spoofed replies harder
    request = build_query(txid, req.domain, qtype)
    exchange = send_query(request, req.server, DNS_PORT, req.timeout, txid)
    message = parse_response(exchange.response)
    if message.header.txid != txid:
        raise MalformedResponse(
            f"transaction ID mismatch: sent 0x{txid:04x}, got 0x{message.header.txid:04x}"
        )
    if not message.header.flags.qr:
        raise MalformedResponse("QR flag is 0: the packet is a query, not a response")

    cache.put(key, message, exchange)
    return build_response(
        req, message, exchange,
        cache_status="BYPASS" if req.bypass_cache else "MISS", ttl_remaining=None,
        rtt_ms=exchange.rtt_ms,
    )


def build_response(
    req: ResolveRequest,
    message: DnsMessage,
    exchange: Exchange,
    *,
    cache_status: str,
    ttl_remaining: int | None,
    rtt_ms: float | None,
) -> ResolveResponse:
    qtype = QTYPE_CODES[req.qtype]
    header = message.header
    question = message.questions[0] if message.questions else None
    return ResolveResponse(
        query=QueryOut(
            domain=req.domain, qtype=req.qtype, server=exchange.server, port=exchange.port,
            transaction_id=header.txid,
        ),
        header=HeaderOut(
            transaction_id=header.txid,
            flags=FlagsOut(**asdict(header.flags), rcode_name=header.flags.rcode_name),
            qdcount=header.qdcount, ancount=header.ancount,
            nscount=header.nscount, arcount=header.arcount,
        ),
        question=(
            QuestionOut(name=question.name, type=rtype_name(question.qtype),
                        rr_class=rclass_name(question.qclass))
            if question else None
        ),
        answers=[_record_out(rr) for rr in message.answers],
        authority=[_record_out(rr) for rr in message.authority],
        additional=[_record_out(rr) for rr in message.additional],
        resolved_ips=[rr.data for rr in message.answers if rr.rtype == qtype],
        timing=TimingOut(rtt_ms=round(rtt_ms, 2) if rtt_ms is not None else None),
        cache=CacheOut(status=cache_status, ttl_remaining=ttl_remaining),
        packets=PacketsOut(
            query=PacketOut(
                hex=exchange.request.hex(),
                spans=[_span_out(s) for s in build_query_spans(header.txid, req.domain, qtype)],
            ),
            response=PacketOut(
                hex=exchange.response.hex(), spans=[_span_out(s) for s in message.spans]
            ),
        ),
    )


def _record_out(rr: ResourceRecord) -> RecordOut:
    return RecordOut(
        name=rr.name or "<root>", type=rtype_name(rr.rtype), type_code=rr.rtype,
        rr_class=rclass_name(rr.rclass), ttl=rr.ttl, rdlength=rr.rdlength, data=rr.data,
    )


def _span_out(span: Span) -> SpanOut:
    return SpanOut(**asdict(span))
```

- [ ] **Step 5: Run to verify pass, lint, commit**

`uv run pytest tests/test_service.py -v` → 6 PASS. `uv run ruff check . && uv run ruff format .`

```bash
git add dns-resolver-app/backend
git commit -m "feat(backend): resolve service wiring cache, transport and parser

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 10: FastAPI app — routes, error handlers, health, logging

**Files:**
- Create: `backend/app/api/resolve.py`, `backend/app/main.py`
- Test: `backend/tests/test_api.py`

**Interfaces:**
- Consumes: `service.resolve`, `TtlCache`, `Settings`/`get_settings`, schemas, `DnsError` subclasses.
- Produces: `create_app(settings: Settings | None = None) -> FastAPI` and module-level `app`; routes `POST /api/v1/resolve`, `DELETE /api/v1/cache` (204), `GET /health`; `app.state.cache: TtlCache`.

- [ ] **Step 1: Write the failing tests `backend/tests/test_api.py`**

```python
import pytest
from fastapi.testclient import TestClient

from app import service
from app.dns.errors import MalformedResponse, NetworkError, QueryTimeout
from app.main import create_app
from tests.fakes import fake_send, raising_send

BODY = {"domain": "www.microsoft.com", "server": "8.8.8.8"}


@pytest.fixture
def client(monkeypatch, load_fixture):
    monkeypatch.setattr(service, "send_query", fake_send(load_fixture, "www_microsoft_com_cname.hex"))
    with TestClient(create_app()) as test_client:  # context manager runs the lifespan
        yield test_client


def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200 and res.json() == {"status": "ok", "cache_entries": 0}


def test_resolve_200_shape(client):
    res = client.post("/api/v1/resolve", json=BODY)
    assert res.status_code == 200
    body = res.json()
    assert set(body) == {
        "query", "header", "question", "answers", "authority", "additional",
        "resolved_ips", "timing", "cache", "packets",
    }
    assert body["query"] == {
        "domain": "www.microsoft.com", "qtype": "A", "server": "8.8.8.8", "port": 53,
        "transaction_id": body["header"]["transaction_id"],
    }
    assert body["header"]["flags"]["rcode_name"] == "NOERROR"
    assert body["question"]["class"] == "IN"  # alias, not rr_class
    assert body["answers"][0]["type"] == "CNAME" and "class" in body["answers"][0]
    assert body["cache"] == {"status": "MISS", "ttl_remaining": None}
    assert body["timing"]["rtt_ms"] == 12.5
    assert {"section", "field", "start", "end", "value"} <= set(body["packets"]["response"]["spans"][0])


def test_second_call_hits_cache_and_delete_clears_it(client):
    client.post("/api/v1/resolve", json=BODY)
    assert client.post("/api/v1/resolve", json=BODY).json()["cache"]["status"] == "HIT"
    assert client.get("/health").json()["cache_entries"] == 1
    assert client.delete("/api/v1/cache").status_code == 204
    assert client.post("/api/v1/resolve", json=BODY).json()["cache"]["status"] == "MISS"


@pytest.mark.parametrize(
    "override, fragment",
    [
        ({"server": "not-an-ip"}, "server: server must be an IPv4 address"),
        ({"domain": "a..b"}, "domain: domain contains an empty label"),
        ({"timeout": 99}, "timeout:"),
        ({"qtype": "MX"}, "qtype:"),
    ],
)
def test_validation_errors_use_uniform_shape(client, override, fragment):
    res = client.post("/api/v1/resolve", json={**BODY, **override})
    assert res.status_code == 422
    body = res.json()
    assert body["error"] == "validation_error" and body["detail"].startswith(fragment)


def test_idna_domain_is_sent_as_punycode(client, monkeypatch, load_fixture):
    seen = {}

    def spy(request, server, port, timeout, expected_txid):
        seen["request"] = request
        return fake_send(load_fixture, "google_com_a.hex")(request, server, port, timeout, expected_txid)

    monkeypatch.setattr(service, "send_query", spy)
    res = client.post("/api/v1/resolve", json={"domain": "bücher.example", "server": "8.8.8.8"})
    assert res.status_code == 200 and res.json()["query"]["domain"] == "xn--bcher-kva.example"
    assert b"\x0dxn--bcher-kva\x07example\x00" in seen["request"]  # 13-byte label


@pytest.mark.parametrize(
    "exc, status, code",
    [
        (QueryTimeout("8.8.8.8", 53, 5.0), 504, "timeout"),
        (MalformedResponse("compression pointer loop"), 502, "malformed_response"),
        (NetworkError("[WinError 10054] connection reset"), 503, "network_error"),
    ],
)
def test_dns_errors_map_to_http_status(client, monkeypatch, exc, status, code):
    monkeypatch.setattr(service, "send_query", raising_send(exc))
    res = client.post("/api/v1/resolve", json=BODY)
    assert res.status_code == status
    assert res.json() == {"error": code, "detail": str(exc)}
```

- [ ] **Step 2: Run to verify failure**

`uv run pytest tests/test_api.py -v` — expected: ImportError for `app.main`.

- [ ] **Step 3: Write `backend/app/api/resolve.py`**

```python
import logging

from fastapi import APIRouter, Request, Response, status
from starlette.concurrency import run_in_threadpool

from app import service
from app.schemas import ErrorResponse, ResolveRequest, ResolveResponse

log = logging.getLogger("dns")
router = APIRouter(prefix="/api/v1", tags=["dns"])

ERROR_RESPONSES = {
    422: {"model": ErrorResponse, "description": "Invalid domain, server, qtype or timeout"},
    502: {"model": ErrorResponse, "description": "Response could not be parsed"},
    503: {"model": ErrorResponse, "description": "Network error talking to the server"},
    504: {"model": ErrorResponse, "description": "Server did not answer in time"},
}


@router.post("/resolve", response_model=ResolveResponse, responses=ERROR_RESPONSES)
async def resolve(body: ResolveRequest, request: Request) -> ResolveResponse:
    """Send a raw DNS query over UDP to ``server:53`` and return the parsed response."""
    # The transport is blocking socket code (as in the CLI); keep it off the event loop.
    result = await run_in_threadpool(service.resolve, body, request.app.state.cache)
    log.info(
        "resolve domain=%s qtype=%s server=%s rcode=%s cache=%s rtt_ms=%s",
        body.domain, body.qtype, body.server, result.header.flags.rcode_name,
        result.cache.status, result.timing.rtt_ms,
    )
    return result


@router.delete("/cache", status_code=status.HTTP_204_NO_CONTENT)
async def clear_cache(request: Request) -> Response:
    """Drop every cached answer (handy for demonstrating a MISS again)."""
    request.app.state.cache.clear()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
```

- [ ] **Step 4: Write `backend/app/main.py`**

```python
"""FastAPI application factory."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.resolve import router
from app.config import Settings, get_settings
from app.dns.cache import TtlCache
from app.dns.errors import MalformedResponse, NetworkError, QueryTimeout
from app.schemas import HealthOut

DESCRIPTION = """
Resolves domain names by building DNS query packets with `struct`, sending them over a UDP
socket to port 53, and parsing the raw response — no resolver library involved.
Built for CS3001 Computer Networks, Assignment 1 (FAST-NUCES Karachi).
"""


def _error(status_code: int, code: str, detail: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": code, "detail": detail})


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(
        level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.cache = TtlCache(max_entries=settings.cache_max_entries)
        yield

    app = FastAPI(
        title="DNS Resolver API", version="0.1.0", description=DESCRIPTION, lifespan=lifespan
    )
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware, allow_origins=settings.cors_origins,
            allow_methods=["*"], allow_headers=["*"],
        )
    app.include_router(router)

    @app.get("/health", response_model=HealthOut, tags=["ops"])
    async def health(request: Request) -> HealthOut:
        return HealthOut(status="ok", cache_entries=len(request.app.state.cache))

    @app.exception_handler(RequestValidationError)
    async def on_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        first = exc.errors()[0]
        location = ".".join(str(part) for part in first["loc"] if part != "body")
        message = str(first["msg"]).removeprefix("Value error, ")
        return _error(422, "validation_error", f"{location}: {message}" if location else message)

    @app.exception_handler(QueryTimeout)
    async def on_timeout(request: Request, exc: QueryTimeout) -> JSONResponse:
        return _error(504, "timeout", str(exc))

    @app.exception_handler(MalformedResponse)
    async def on_malformed(request: Request, exc: MalformedResponse) -> JSONResponse:
        return _error(502, "malformed_response", str(exc))

    @app.exception_handler(NetworkError)
    async def on_network_error(request: Request, exc: NetworkError) -> JSONResponse:
        return _error(503, "network_error", str(exc))

    return app


app = create_app()
```

- [ ] **Step 5: Run the whole suite, lint, and try the server for real**

`uv run pytest -v` → all PASS. `uv run ruff check . && uv run ruff format .`

Then from `backend/` start it: `uv run uvicorn app.main:app --port 8000` and in another shell:
```bash
curl -s -X POST localhost:8000/api/v1/resolve -H "content-type: application/json" -d '{"domain":"www.microsoft.com","server":"8.8.8.8"}' | python -m json.tool | head -40
curl -s -X POST localhost:8000/api/v1/resolve -H "content-type: application/json" -d '{"domain":"google.com","server":"not-an-ip"}'
```
Expected: first prints a JSON document with `"rcode_name": "NOERROR"` and a CNAME answer; second prints `{"error":"validation_error","detail":"server: server must be an IPv4 address, e.g. 8.8.8.8"}`. Open `http://localhost:8000/docs` — Swagger UI lists the three routes. Stop the server.

- [ ] **Step 6: Commit**

```bash
git add dns-resolver-app/backend
git commit -m "feat(backend): FastAPI app with resolve/cache/health routes and error mapping

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 11: Backend Dockerfile

**Files:**
- Create: `backend/Dockerfile`, `backend/.dockerignore`
- Verify: `backend/uv.lock` exists and is committed (created by `uv sync` in Task 1).

**Interfaces:**
- Produces: image serving on `:8000` with a `HEALTHCHECK` on `/health`, running as non-root.

- [ ] **Step 1: Write `backend/.dockerignore`**

```
.venv
__pycache__
*.pyc
.pytest_cache
.ruff_cache
tests
```

- [ ] **Step 2: Write `backend/Dockerfile`**

```dockerfile
FROM python:3.13-slim

COPY --from=ghcr.io/astral-sh/uv:0.4 /uv /usr/local/bin/uv

ENV PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

# Dependencies first so this layer is cached across code changes
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY app ./app

RUN useradd --system --uid 10001 --no-create-home app && chown -R app:app /app
USER app

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"]

# One worker on purpose: the TTL cache lives in this process
CMD ["/app/.venv/bin/uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
```

If `ghcr.io/astral-sh/uv:0.4` is not pullable, use `ghcr.io/astral-sh/uv:latest`.

- [ ] **Step 3: Build and run the image**

From `dns-resolver-app/`:
```bash
docker build -t dns-backend ./backend
docker run --rm -d --name dns-backend-test -p 8000:8000 dns-backend
sleep 6
docker inspect --format '{{.State.Health.Status}}' dns-backend-test
curl -s -X POST localhost:8000/api/v1/resolve -H "content-type: application/json" -d '{"domain":"google.com","server":"8.8.8.8"}' | python -c "import json,sys; d=json.load(sys.stdin); print(d['header']['flags']['rcode_name'], d['resolved_ips'], d['timing'])"
docker rm -f dns-backend-test
```
Expected: health `healthy`; the resolve line prints `NOERROR ['142.250....'] {'rtt_ms': <number>}` (UDP egress from the container works over the default bridge).

- [ ] **Step 4: Commit**

```bash
git add dns-resolver-app/backend
git commit -m "build(backend): Dockerfile with uv, non-root user and healthcheck

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 12: Frontend scaffold, Vitest, and the `hexdump` utility

**Files:**
- Create (via `create-next-app`): `frontend/` — then edit `frontend/package.json`, `frontend/next.config.ts`, `frontend/src/app/globals.css`, `frontend/src/app/layout.tsx`, `frontend/src/app/page.tsx`
- Create: `frontend/vitest.config.ts`, `frontend/src/lib/hexdump.ts`
- Test: `frontend/src/lib/hexdump.test.ts`

**Interfaces:**
- Produces: `type Span = { section: string; field: string; start: number; end: number; value: string }`, `type Cell = { offset: number; byte: number; hex: string; ascii: string; span: Span | null }`, `type Row = { offset: number; cells: Cell[] }`, `hexToBytes(hex: string): Uint8Array`, `spanAt(spans: Span[], offset: number): Span | null`, `hexdump(bytes: Uint8Array, spans: Span[], width?: number): Row[]`. npm scripts `dev`, `build`, `start`, `lint`, `typecheck`, `test`.

- [ ] **Step 1: Scaffold with create-next-app**

From `dns-resolver-app/`:
```bash
npx --yes create-next-app@latest frontend --yes --ts --tailwind --eslint --app --src-dir --import-alias "@/*" --use-npm
```
Expected: `frontend/` with `src/app/{layout,page}.tsx`, `globals.css`, `next.config.ts`, `eslint.config.mjs`, `tsconfig.json`. Whatever Next major it installs (15 or 16) is fine — the code below uses only stable App Router APIs. Delete the boilerplate assets: `rm frontend/public/*.svg`.

- [ ] **Step 2: Add Vitest and scripts**

From `frontend/`: `npm install --save-dev vitest`. In `package.json` make sure `scripts` contains (keep the `lint` script create-next-app generated):
```json
"dev": "next dev",
"build": "next build",
"start": "next start",
"typecheck": "tsc --noEmit",
"test": "vitest run"
```

`frontend/vitest.config.ts`:
```ts
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: { include: ["src/**/*.test.ts"], environment: "node" },
});
```

`frontend/next.config.ts`:
```ts
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone", // Docker: self-contained server.js in .next/standalone
};

export default nextConfig;
```

- [ ] **Step 3: Replace `globals.css`, `layout.tsx`, `page.tsx` with the app shell**

`frontend/src/app/globals.css`:
```css
@import "tailwindcss";

:root {
  --sec-header: #f59e0b;
  --sec-question: #38bdf8;
  --sec-answer: #34d399;
  --sec-authority: #a78bfa;
  --sec-additional: #f472b6;
  --sec-trailing: #71717a;
}

body {
  @apply bg-zinc-950 text-zinc-100 antialiased;
}
```

`frontend/src/app/layout.tsx`:
```tsx
import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "DNS Resolver",
  description: "Raw-socket DNS lookups with an annotated packet view — CS3001 Assignment 1",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen font-sans">{children}</body>
    </html>
  );
}
```

`frontend/src/app/page.tsx` (temporary shell; Task 14 replaces it):
```tsx
export default function Page() {
  return (
    <main className="mx-auto max-w-5xl px-4 py-10">
      <h1 className="text-2xl font-semibold">DNS Resolver</h1>
    </main>
  );
}
```

- [ ] **Step 4: Write the failing tests `frontend/src/lib/hexdump.test.ts`**

```ts
import { describe, expect, it } from "vitest";
import { hexToBytes, hexdump, spanAt, type Span } from "./hexdump";

const spans: Span[] = [
  { section: "header", field: "ID", start: 0, end: 2, value: "0x1234" },
  { section: "header", field: "FLAGS", start: 2, end: 4, value: "RD" },
  { section: "question", field: "QNAME", start: 4, end: 20, value: "www.example.com" },
];

describe("hexToBytes", () => {
  it("decodes lower-case hex without separators", () => {
    expect(Array.from(hexToBytes("1234abff"))).toEqual([0x12, 0x34, 0xab, 0xff]);
  });
  it("rejects odd length or non-hex input", () => {
    expect(() => hexToBytes("123")).toThrow();
    expect(() => hexToBytes("zz")).toThrow();
  });
});

describe("spanAt", () => {
  it("finds the covering span and returns null outside any span", () => {
    expect(spanAt(spans, 0)?.field).toBe("ID");
    expect(spanAt(spans, 3)?.field).toBe("FLAGS");
    expect(spanAt(spans, 25)).toBeNull();
  });
  it("last span wins when spans overlap", () => {
    const overlapping = [...spans, { section: "answer", field: "X", start: 1, end: 3, value: "" }];
    expect(spanAt(overlapping, 2)?.field).toBe("X");
  });
});

describe("hexdump", () => {
  it("splits bytes into rows of the given width with offsets", () => {
    const rows = hexdump(new Uint8Array(20), spans, 16);
    expect(rows).toHaveLength(2);
    expect(rows[0].offset).toBe(0);
    expect(rows[1].offset).toBe(16);
    expect(rows[1].cells).toHaveLength(4);
  });
  it("renders printable ASCII and dots otherwise, and attaches spans", () => {
    const rows = hexdump(hexToBytes("12340377777700"), spans, 16);
    const cells = rows[0].cells;
    expect(cells.map((c) => c.hex).join(" ")).toBe("12 34 03 77 77 77 00");
    expect(cells.map((c) => c.ascii).join("")).toBe(".4.www."); // 0x34 is printable '4'
    expect(cells[0].span?.field).toBe("ID");
    expect(cells[4].span?.section).toBe("question");
  });
});
```

- [ ] **Step 5: Run to verify failure**

From `frontend/`: `npm test` — expected: fails to resolve `./hexdump`.

- [ ] **Step 6: Write `frontend/src/lib/hexdump.ts`**

```ts
/** Pure helpers that turn a packet (hex) plus backend spans into rows for the hex-dump view. */

export type Span = { section: string; field: string; start: number; end: number; value: string };
export type Cell = { offset: number; byte: number; hex: string; ascii: string; span: Span | null };
export type Row = { offset: number; cells: Cell[] };

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, "");
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
    throw new Error("invalid hex string");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** The last span covering `offset` wins, so a later, narrower span overrides an earlier one. */
export function spanAt(spans: Span[], offset: number): Span | null {
  let found: Span | null = null;
  for (const span of spans) {
    if (offset >= span.start && offset < span.end) found = span;
  }
  return found;
}

export function hexdump(bytes: Uint8Array, spans: Span[], width = 16): Row[] {
  const rows: Row[] = [];
  for (let start = 0; start < bytes.length; start += width) {
    const cells: Cell[] = [];
    for (let offset = start; offset < Math.min(start + width, bytes.length); offset++) {
      const byte = bytes[offset];
      cells.push({
        offset,
        byte,
        hex: byte.toString(16).padStart(2, "0"),
        ascii: byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".",
        span: spanAt(spans, offset),
      });
    }
    rows.push({ offset: start, cells });
  }
  return rows;
}
```

- [ ] **Step 7: Verify tests, types, lint, build**

From `frontend/`: `npm test` → all PASS; `npm run typecheck` → clean; `npm run lint` → clean; `npm run build` → succeeds and prints the `/` route.

- [ ] **Step 8: Commit**

```bash
git add dns-resolver-app/frontend
git commit -m "feat(frontend): Next.js scaffold, Vitest, hexdump utility

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 13: API client types and the runtime proxy route

**Files:**
- Create: `frontend/src/lib/api.ts`, `frontend/src/app/api/[...path]/route.ts`

**Interfaces:**
- Consumes: backend routes from Task 10.
- Produces: types `ResolveRequest`, `ResolveResponse`, `RecordOut`, `FlagsOut`, `Packet`, `CacheStatus`; `class ApiError extends Error { status: number; code: string; detail: string }`; `resolveDomain(req: ResolveRequest): Promise<ResolveResponse>`; `clearCache(): Promise<void>`. Proxy: any `/api/*` request on the Next server is forwarded to `${API_URL}/api/*` (default `http://localhost:8000`).

- [ ] **Step 1: Write `frontend/src/lib/api.ts`**

```ts
/** Typed client for the backend. Calls go to same-origin /api/* and are proxied server-side. */

import type { Span } from "./hexdump";

export type QType = "A" | "AAAA";
export type CacheStatus = "HIT" | "MISS" | "BYPASS";

export type ResolveRequest = {
  domain: string;
  server: string;
  qtype: QType;
  timeout?: number;
  bypass_cache: boolean;
};

export type FlagsOut = {
  raw: number; qr: boolean; opcode: number; aa: boolean; tc: boolean; rd: boolean;
  ra: boolean; ad: boolean; cd: boolean; rcode: number; rcode_name: string;
};

export type HeaderOut = {
  transaction_id: number; flags: FlagsOut;
  qdcount: number; ancount: number; nscount: number; arcount: number;
};

export type QuestionOut = { name: string; type: string; class: string };

export type RecordOut = {
  name: string; type: string; type_code: number; class: string;
  ttl: number; rdlength: number; data: string;
};

export type Packet = { hex: string; spans: Span[] };

export type ResolveResponse = {
  query: { domain: string; qtype: QType; server: string; port: number; transaction_id: number };
  header: HeaderOut;
  question: QuestionOut | null;
  answers: RecordOut[];
  authority: RecordOut[];
  additional: RecordOut[];
  resolved_ips: string[];
  timing: { rtt_ms: number | null };
  cache: { status: CacheStatus; ttl_remaining: number | null };
  packets: { query: Packet; response: Packet };
};

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    public readonly detail: string,
  ) {
    super(detail);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, init);
  } catch {
    throw new ApiError(0, "network_error", "Could not reach the API server");
  }
  if (res.status === 204) return undefined as T;
  const body: unknown = await res.json().catch(() => null);
  if (!res.ok) {
    const err = (body ?? {}) as { error?: string; detail?: string };
    throw new ApiError(res.status, err.error ?? "unknown_error", err.detail ?? res.statusText);
  }
  return body as T;
}

export function resolveDomain(req: ResolveRequest): Promise<ResolveResponse> {
  return request<ResolveResponse>("/api/v1/resolve", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(req),
  });
}

export function clearCache(): Promise<void> {
  return request<void>("/api/v1/cache", { method: "DELETE" });
}
```

- [ ] **Step 2: Write `frontend/src/app/api/[...path]/route.ts`**

```ts
/**
 * Runtime proxy: forwards /api/<path> to the backend named by API_URL.
 * Read per request (not at build time) so docker-compose can set API_URL=http://backend:8000.
 */
import type { NextRequest } from "next/server";

type Ctx = { params: Promise<{ path: string[] }> };

async function proxy(req: NextRequest, { params }: Ctx): Promise<Response> {
  const apiUrl = process.env.API_URL ?? "http://localhost:8000";
  const { path } = await params;
  const url = `${apiUrl}/api/${path.join("/")}${req.nextUrl.search}`;

  const headers = new Headers();
  const contentType = req.headers.get("content-type");
  if (contentType) headers.set("content-type", contentType);
  const body = req.method === "GET" || req.method === "HEAD" ? undefined : await req.text();

  let upstream: Response;
  try {
    upstream = await fetch(url, { method: req.method, headers, body, cache: "no-store" });
  } catch {
    return Response.json(
      { error: "network_error", detail: `API server at ${apiUrl} is unreachable` },
      { status: 503 },
    );
  }

  const responseHeaders = new Headers();
  const upstreamType = upstream.headers.get("content-type");
  if (upstreamType) responseHeaders.set("content-type", upstreamType);
  return new Response(upstream.body, { status: upstream.status, headers: responseHeaders });
}

export { proxy as GET, proxy as POST, proxy as DELETE };
```

- [ ] **Step 3: Verify the proxy end to end**

Terminal 1, from `backend/`: `uv run uvicorn app.main:app --port 8000`.
Terminal 2, from `frontend/`: `npm run dev`.
Terminal 3:
```bash
curl -s -X POST localhost:3000/api/v1/resolve -H "content-type: application/json" -d '{"domain":"google.com","server":"8.8.8.8","qtype":"A","bypass_cache":false}' | python -c "import json,sys; d=json.load(sys.stdin); print(d['cache'], d['resolved_ips'])"
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE localhost:3000/api/v1/cache
curl -s -X POST localhost:3000/api/v1/resolve -H "content-type: application/json" -d '{"domain":"x","server":"nope"}'
```
Expected: `{'status': 'MISS', ...} ['…']`, then `204`, then the backend's 422 JSON passed through unchanged. Also `npm run typecheck && npm run lint` clean. Stop both servers.

- [ ] **Step 4: Commit**

```bash
git add dns-resolver-app/frontend
git commit -m "feat(frontend): typed API client and runtime proxy route

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 14: Page, `ResolveForm`, `StatusStrip`, `ErrorCard`

**Files:**
- Create: `frontend/src/components/ResolveForm.tsx`, `frontend/src/components/StatusStrip.tsx`, `frontend/src/components/ErrorCard.tsx`, `frontend/src/components/Badge.tsx`
- Modify: `frontend/src/app/page.tsx` (replace the shell)

**Interfaces:**
- Consumes: `resolveDomain`, `clearCache`, `ApiError`, types from Task 13.
- Produces: `<ResolveForm loading onSubmit(req) onClearCache() />`, `<StatusStrip result />` (mount with a changing `key` so its TTL countdown restarts per result), `<ErrorCard error />`, `<Badge tone children />` with `tone: "green" | "red" | "amber" | "blue" | "zinc"`. Page state machine `idle | loading | success | error`. Tasks 15–16 add components into the `success` branch where marked.

- [ ] **Step 1: Write `frontend/src/components/Badge.tsx`**

```tsx
export type Tone = "green" | "red" | "amber" | "blue" | "zinc";

const TONES: Record<Tone, string> = {
  green: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
  red: "bg-red-500/15 text-red-300 ring-red-500/30",
  amber: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  blue: "bg-sky-500/15 text-sky-300 ring-sky-500/30",
  zinc: "bg-zinc-500/15 text-zinc-300 ring-zinc-500/30",
};

export function Badge({ tone, children }: { tone: Tone; children: React.ReactNode }) {
  return (
    <span className={`inline-flex items-center rounded-md px-2 py-0.5 font-mono text-xs font-medium ring-1 ring-inset ${TONES[tone]}`}>
      {children}
    </span>
  );
}
```

- [ ] **Step 2: Write `frontend/src/components/ResolveForm.tsx`**

```tsx
"use client";

import { useState, type FormEvent } from "react";
import type { QType, ResolveRequest } from "@/lib/api";

const PRESETS = [
  { label: "Google · 8.8.8.8", value: "8.8.8.8" },
  { label: "Cloudflare · 1.1.1.1", value: "1.1.1.1" },
  { label: "Quad9 · 9.9.9.9", value: "9.9.9.9" },
  { label: "Custom…", value: "custom" },
] as const;

type Props = {
  loading: boolean;
  onSubmit: (req: ResolveRequest) => void;
  onClearCache: () => void;
};

const field =
  "rounded-md border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-zinc-500";

export function ResolveForm({ loading, onSubmit, onClearCache }: Props) {
  const [domain, setDomain] = useState("");
  const [preset, setPreset] = useState<string>("8.8.8.8");
  const [custom, setCustom] = useState("");
  const [qtype, setQtype] = useState<QType>("A");
  const [bypass, setBypass] = useState(false);
  const server = preset === "custom" ? custom : preset;

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!domain.trim() || !server.trim()) return;
    onSubmit({ domain: domain.trim(), server: server.trim(), qtype, bypass_cache: bypass });
  }

  return (
    <form onSubmit={submit} className="grid gap-3 rounded-lg border border-zinc-800 bg-zinc-900/40 p-4">
      <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
        <label className="grid gap-1 text-xs text-zinc-400">
          Domain
          <input
            autoFocus
            className={field}
            placeholder="www.example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            spellCheck={false}
            autoCapitalize="none"
          />
        </label>
        <label className="grid gap-1 text-xs text-zinc-400">
          Record type
          <div className="flex overflow-hidden rounded-md border border-zinc-800">
            {(["A", "AAAA"] as QType[]).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setQtype(t)}
                className={`px-4 py-2 font-mono text-sm ${qtype === t ? "bg-zinc-100 text-zinc-900" : "bg-zinc-900 text-zinc-300"}`}
              >
                {t}
              </button>
            ))}
          </div>
        </label>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <label className="grid gap-1 text-xs text-zinc-400">
          DNS server (UDP port 53)
          <select className={field} value={preset} onChange={(e) => setPreset(e.target.value)}>
            {PRESETS.map((p) => (
              <option key={p.value} value={p.value}>{p.label}</option>
            ))}
          </select>
        </label>
        {preset === "custom" && (
          <label className="grid gap-1 text-xs text-zinc-400">
            Custom server IPv4
            <input
              className={field}
              placeholder="192.168.1.1"
              value={custom}
              onChange={(e) => setCustom(e.target.value)}
            />
          </label>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <button
          type="submit"
          disabled={loading}
          className="rounded-md bg-zinc-100 px-4 py-2 text-sm font-medium text-zinc-900 disabled:opacity-50"
        >
          {loading ? "Resolving…" : "Resolve"}
        </button>
        <button
          type="button"
          onClick={onClearCache}
          className="rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-300 hover:border-zinc-500"
        >
          Clear cache
        </button>
        <label className="ml-auto flex items-center gap-2 text-sm text-zinc-400">
          <input type="checkbox" checked={bypass} onChange={(e) => setBypass(e.target.checked)} />
          Skip cache
        </label>
      </div>
    </form>
  );
}
```

- [ ] **Step 3: Write `frontend/src/components/StatusStrip.tsx`**

```tsx
"use client";

import { useEffect, useState } from "react";
import type { ResolveResponse } from "@/lib/api";
import { Badge, type Tone } from "./Badge";

function rcodeTone(name: string): Tone {
  if (name === "NOERROR") return "green";
  if (name === "NXDOMAIN" || name === "SERVFAIL" || name === "REFUSED") return "red";
  return "amber";
}

const CACHE_TONE: Record<ResolveResponse["cache"]["status"], Tone> = {
  HIT: "amber",
  MISS: "zinc",
  BYPASS: "blue",
};

/** Mount with a fresh `key` per result: the TTL countdown is seeded from props once. */
export function StatusStrip({ result }: { result: ResolveResponse }) {
  const initialTtl = result.cache.ttl_remaining;
  const [ttl, setTtl] = useState(initialTtl);

  useEffect(() => {
    if (initialTtl == null) return;
    const id = setInterval(() => setTtl((t) => (t == null || t <= 0 ? 0 : t - 1)), 1000);
    return () => clearInterval(id);
  }, [initialTtl]);

  const { header, cache, timing, query } = result;
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border border-zinc-800 bg-zinc-900/40 px-4 py-3 text-sm">
      <Badge tone={rcodeTone(header.flags.rcode_name)}>{header.flags.rcode_name}</Badge>
      <Badge tone={CACHE_TONE[cache.status]}>
        {cache.status}
        {cache.status === "HIT" && ttl != null && ` · ${ttl}s TTL left`}
      </Badge>
      <span className="text-zinc-400">
        RTT{" "}
        <span className="font-mono text-zinc-100">
          {timing.rtt_ms == null ? "— (cached)" : `${timing.rtt_ms} ms`}
        </span>
      </span>
      <span className="text-zinc-400">
        ID{" "}
        <span className="font-mono text-zinc-100">
          0x{header.transaction_id.toString(16).padStart(4, "0")} ({header.transaction_id})
        </span>
      </span>
      <span className="text-zinc-400">
        via <span className="font-mono text-zinc-100">{query.server}:{query.port}</span>
      </span>
      {result.resolved_ips.length > 0 && (
        <span className="ml-auto font-mono text-emerald-300">{result.resolved_ips.join("  ")}</span>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Write `frontend/src/components/ErrorCard.tsx`**

```tsx
import type { ApiError } from "@/lib/api";

const COPY: Record<string, { title: string; hint: string }> = {
  timeout: {
    title: "Timeout",
    hint: "The server never answered. Check the IP, or try a public resolver such as 8.8.8.8.",
  },
  malformed_response: {
    title: "Malformed response",
    hint: "Bytes came back but could not be parsed as a DNS response for this query.",
  },
  network_error: {
    title: "Network error",
    hint: "The OS could not send the packet or the host refused it (ICMP port unreachable).",
  },
  validation_error: {
    title: "Invalid input",
    hint: "Fix the highlighted field and try again.",
  },
};

export function ErrorCard({ error }: { error: ApiError }) {
  const copy = COPY[error.code] ?? { title: "Request failed", hint: "" };
  return (
    <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-4">
      <div className="flex items-baseline gap-3">
        <h2 className="font-semibold text-red-200">{copy.title}</h2>
        {error.status > 0 && <span className="font-mono text-xs text-red-300/70">HTTP {error.status} · {error.code}</span>}
      </div>
      <p className="mt-1 font-mono text-sm text-red-100">{error.detail}</p>
      {copy.hint && <p className="mt-2 text-sm text-red-200/70">{copy.hint}</p>}
    </div>
  );
}
```

- [ ] **Step 5: Replace `frontend/src/app/page.tsx`**

```tsx
"use client";

import { useState } from "react";
import { ApiError, clearCache, resolveDomain, type ResolveRequest, type ResolveResponse } from "@/lib/api";
import { ErrorCard } from "@/components/ErrorCard";
import { ResolveForm } from "@/components/ResolveForm";
import { StatusStrip } from "@/components/StatusStrip";

type State =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "success"; result: ResolveResponse; seq: number }
  | { status: "error"; error: ApiError };

export default function Page() {
  const [state, setState] = useState<State>({ status: "idle" });
  const [seq, setSeq] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);

  async function handleSubmit(req: ResolveRequest) {
    setState({ status: "loading" });
    try {
      const result = await resolveDomain(req);
      const next = seq + 1;
      setSeq(next);
      setState({ status: "success", result, seq: next });
    } catch (err) {
      const error = err instanceof ApiError ? err : new ApiError(0, "unknown_error", String(err));
      setState({ status: "error", error });
    }
  }

  async function handleClearCache() {
    try {
      await clearCache();
      setNotice("Cache cleared — the next lookup will be a MISS");
    } catch (err) {
      setNotice(err instanceof ApiError ? err.detail : "Could not clear the cache");
    }
    setTimeout(() => setNotice(null), 2500);
  }

  return (
    <main className="mx-auto grid max-w-5xl gap-4 px-4 py-8">
      <header className="flex flex-wrap items-baseline justify-between gap-2">
        <h1 className="text-2xl font-semibold tracking-tight">DNS Resolver</h1>
        <p className="text-sm text-zinc-400">
          Hand-built query packets over UDP/53 · parsed byte by byte · CS3001 Assignment 1
        </p>
      </header>

      <ResolveForm loading={state.status === "loading"} onSubmit={handleSubmit} onClearCache={handleClearCache} />
      {notice && <p className="text-sm text-amber-300">{notice}</p>}

      {state.status === "error" && <ErrorCard error={state.error} />}
      {state.status === "success" && (
        <>
          <StatusStrip key={state.seq} result={state.result} />
          {/* Task 15: HeaderCard, QuestionCard, RecordsTable go here */}
          {/* Task 16: PacketInspector goes here */}
        </>
      )}
    </main>
  );
}
```

- [ ] **Step 6: Verify**

From `frontend/`: `npm run typecheck && npm run lint && npm run build` → all clean. Then run backend (`uv run uvicorn app.main:app --port 8000` from `backend/`) and `npm run dev`, open `http://localhost:3000`, resolve `google.com` twice: first shows `NOERROR · MISS · RTT n ms`, second shows `HIT · Ns TTL left` counting down. Enter `nope` as a custom server → red "Invalid input" card with the backend's detail. Stop servers.

- [ ] **Step 7: Commit**

```bash
git add dns-resolver-app/frontend
git commit -m "feat(frontend): resolve form, status strip with TTL countdown, error card

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 15: `HeaderCard`, `QuestionCard`, `RecordsTable`

**Files:**
- Create: `frontend/src/components/Card.tsx`, `frontend/src/components/HeaderCard.tsx`, `frontend/src/components/QuestionCard.tsx`, `frontend/src/components/RecordsTable.tsx`
- Modify: `frontend/src/app/page.tsx` (fill the Task 15 marker)

**Interfaces:**
- Consumes: `ResolveResponse`, `RecordOut`, `HeaderOut` from Task 13; `Badge` from Task 14.
- Produces: `<Card title>children</Card>`, `<HeaderCard header />`, `<QuestionCard question />`, `<RecordsTable result />`.

- [ ] **Step 1: Write `frontend/src/components/Card.tsx`**

```tsx
export function Card({ title, aside, children }: { title: string; aside?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-zinc-800 bg-zinc-900/40">
      <header className="flex items-center justify-between border-b border-zinc-800 px-4 py-2">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">{title}</h2>
        {aside}
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}
```

- [ ] **Step 2: Write `frontend/src/components/HeaderCard.tsx`**

```tsx
import type { HeaderOut } from "@/lib/api";
import { Card } from "./Card";

const FLAG_HELP: Record<string, string> = {
  QR: "Response (1) vs query (0)",
  AA: "Authoritative answer",
  TC: "Truncated — did not fit in one UDP packet",
  RD: "Recursion desired (we set this)",
  RA: "Recursion available (server recurses)",
  AD: "DNSSEC: authenticated data",
  CD: "DNSSEC: checking disabled",
};

export function HeaderCard({ header }: { header: HeaderOut }) {
  const f = header.flags;
  const bits: [string, boolean][] = [
    ["QR", f.qr], ["AA", f.aa], ["TC", f.tc], ["RD", f.rd], ["RA", f.ra], ["AD", f.ad], ["CD", f.cd],
  ];
  return (
    <Card
      title="Header"
      aside={<span className="font-mono text-xs text-zinc-500">flags 0x{f.raw.toString(16).padStart(4, "0")}</span>}
    >
      <div className="flex flex-wrap gap-2">
        {bits.map(([name, on]) => (
          <span
            key={name}
            title={FLAG_HELP[name]}
            className={`rounded px-2 py-1 font-mono text-xs ring-1 ring-inset ${
              on ? "bg-amber-500/15 text-amber-200 ring-amber-500/40" : "text-zinc-600 ring-zinc-800"
            }`}
          >
            {name}
          </span>
        ))}
        <span className="rounded px-2 py-1 font-mono text-xs text-zinc-400 ring-1 ring-inset ring-zinc-800">
          opcode {f.opcode}
        </span>
        <span className="rounded px-2 py-1 font-mono text-xs text-zinc-400 ring-1 ring-inset ring-zinc-800">
          rcode {f.rcode} {f.rcode_name}
        </span>
      </div>
      <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 font-mono text-sm sm:grid-cols-4">
        {(
          [["QDCOUNT", header.qdcount], ["ANCOUNT", header.ancount], ["NSCOUNT", header.nscount], ["ARCOUNT", header.arcount]] as const
        ).map(([k, v]) => (
          <div key={k} className="flex justify-between gap-2">
            <dt className="text-zinc-500">{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}
```

- [ ] **Step 3: Write `frontend/src/components/QuestionCard.tsx`**

```tsx
import type { QuestionOut } from "@/lib/api";
import { Card } from "./Card";

export function QuestionCard({ question }: { question: QuestionOut | null }) {
  return (
    <Card title="Question">
      {question ? (
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 font-mono text-sm">
          <dt className="text-zinc-500">QNAME</dt><dd>{question.name}</dd>
          <dt className="text-zinc-500">QTYPE</dt><dd>{question.type}</dd>
          <dt className="text-zinc-500">QCLASS</dt><dd>{question.class}</dd>
        </dl>
      ) : (
        <p className="text-sm text-zinc-500">The response carried no question section.</p>
      )}
    </Card>
  );
}
```

- [ ] **Step 4: Write `frontend/src/components/RecordsTable.tsx`**

```tsx
import type { RecordOut, ResolveResponse } from "@/lib/api";
import { Card } from "./Card";

function Table({ records, highlightType }: { records: RecordOut[]; highlightType: string }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full font-mono text-sm">
        <thead className="text-left text-xs uppercase tracking-wider text-zinc-500">
          <tr>
            <th className="py-1 pr-4">Name</th>
            <th className="py-1 pr-4">Type</th>
            <th className="py-1 pr-4">Class</th>
            <th className="py-1 pr-4">TTL</th>
            <th className="py-1">Data</th>
          </tr>
        </thead>
        <tbody>
          {records.map((rr, i) => (
            <tr key={i} className="border-t border-zinc-800/60">
              <td className="py-1.5 pr-4 text-zinc-300">{rr.name}</td>
              <td className="py-1.5 pr-4">{rr.type}</td>
              <td className="py-1.5 pr-4 text-zinc-400">{rr.class}</td>
              <td className="py-1.5 pr-4">{rr.ttl}s</td>
              <td className={`py-1.5 break-all ${rr.type === highlightType ? "font-semibold text-emerald-300" : ""}`}>
                {rr.data}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Section({ title, records, highlightType, open }: { title: string; records: RecordOut[]; highlightType: string; open: boolean }) {
  return (
    <details open={open} className="group">
      <summary className="cursor-pointer select-none text-xs font-semibold uppercase tracking-wider text-zinc-400">
        {title} <span className="font-mono text-zinc-600">({records.length})</span>
      </summary>
      <div className="mt-2">
        {records.length ? <Table records={records} highlightType={highlightType} /> : <p className="text-sm text-zinc-500">none</p>}
      </div>
    </details>
  );
}

export function RecordsTable({ result }: { result: ResolveResponse }) {
  const qtype = result.query.qtype;
  const noAnswers = result.answers.length === 0;
  return (
    <Card title="Resource records">
      <div className="grid gap-4">
        <Section title="Answer" records={result.answers} highlightType={qtype} open />
        <Section title="Authority" records={result.authority} highlightType={qtype} open={noAnswers} />
        <Section title="Additional" records={result.additional} highlightType={qtype} open={false} />
      </div>
    </Card>
  );
}
```

- [ ] **Step 5: Wire into `page.tsx`**

Add the imports:
```tsx
import { HeaderCard } from "@/components/HeaderCard";
import { QuestionCard } from "@/components/QuestionCard";
import { RecordsTable } from "@/components/RecordsTable";
```
Replace the line `{/* Task 15: HeaderCard, QuestionCard, RecordsTable go here */}` with:
```tsx
          <div className="grid gap-4 md:grid-cols-2">
            <HeaderCard header={state.result.header} />
            <QuestionCard question={state.result.question} />
          </div>
          <RecordsTable result={state.result} />
```

- [ ] **Step 6: Verify and commit**

`npm run typecheck && npm run lint && npm run build` clean. With backend + `npm run dev` running: `www.microsoft.com` shows a CNAME row followed by A rows with the A data highlighted; an NXDOMAIN domain shows an empty Answer section and the Authority section open with one SOA row.

```bash
git add dns-resolver-app/frontend
git commit -m "feat(frontend): header, question and resource record cards

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 16: `PacketInspector` — annotated hex dump

**Files:**
- Create: `frontend/src/components/PacketInspector.tsx`
- Modify: `frontend/src/app/page.tsx` (fill the Task 16 marker)

**Interfaces:**
- Consumes: `hexdump`, `hexToBytes`, `Span` (Task 12); `Packet`, `ResolveResponse` (Task 13); `Card` (Task 15).
- Produces: `<PacketInspector result />`.

- [ ] **Step 1: Write `frontend/src/components/PacketInspector.tsx`**

```tsx
"use client";

import { useMemo, useState } from "react";
import type { Packet, ResolveResponse } from "@/lib/api";
import { hexToBytes, hexdump, type Span } from "@/lib/hexdump";
import { Card } from "./Card";

const SECTIONS = ["header", "question", "answer", "authority", "additional", "trailing"] as const;

function sectionColor(section: string | undefined): string {
  return section ? `var(--sec-${section})` : "transparent";
}

function HexDump({ packet }: { packet: Packet }) {
  const rows = useMemo(() => hexdump(hexToBytes(packet.hex), packet.spans), [packet]);
  const [hover, setHover] = useState<Span | null>(null);

  return (
    <div>
      <div className="overflow-x-auto rounded-md border border-zinc-800 bg-zinc-950 p-3 font-mono text-xs leading-6">
        {rows.map((row) => (
          <div key={row.offset} className="flex gap-4 whitespace-nowrap">
            <span className="w-10 shrink-0 text-zinc-600">{row.offset.toString(16).padStart(4, "0")}</span>
            <span className="flex gap-1">
              {row.cells.map((cell) => (
                <span
                  key={cell.offset}
                  title={cell.span ? `${cell.span.section} › ${cell.span.field} = ${cell.span.value}` : `byte ${cell.offset}`}
                  onMouseEnter={() => setHover(cell.span)}
                  onMouseLeave={() => setHover(null)}
                  style={{
                    color: sectionColor(cell.span?.section),
                    backgroundColor: hover && cell.span === hover ? "rgba(255,255,255,0.12)" : undefined,
                  }}
                  className="cursor-default rounded px-0.5"
                >
                  {cell.hex}
                </span>
              ))}
              {row.cells.length < 16 && <span style={{ width: `${(16 - row.cells.length) * 1.5}rem` }} />}
            </span>
            <span className="text-zinc-500">
              {row.cells.map((cell) => (
                <span
                  key={cell.offset}
                  style={{ backgroundColor: hover && cell.span === hover ? "rgba(255,255,255,0.12)" : undefined }}
                >
                  {cell.ascii}
                </span>
              ))}
            </span>
          </div>
        ))}
      </div>
      <div className="mt-2 flex min-h-6 flex-wrap items-center gap-x-4 gap-y-1 text-xs">
        {hover ? (
          <span className="font-mono">
            <span style={{ color: sectionColor(hover.section) }}>{hover.section}</span>
            <span className="text-zinc-500"> › </span>
            <span className="text-zinc-300">{hover.field}</span>
            <span className="text-zinc-500"> = </span>
            <span className="text-zinc-100">{hover.value}</span>
            <span className="text-zinc-600"> [{hover.start}–{hover.end - 1}]</span>
          </span>
        ) : (
          <span className="text-zinc-500">Hover a byte to see its field.</span>
        )}
      </div>
    </div>
  );
}

export function PacketInspector({ result }: { result: ResolveResponse }) {
  const [tab, setTab] = useState<"query" | "response">("response");
  const packet = result.packets[tab];
  const bytes = packet.hex.length / 2;

  return (
    <Card
      title="Packet inspector"
      aside={
        <div className="flex overflow-hidden rounded-md border border-zinc-800 text-xs">
          {(["query", "response"] as const).map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => setTab(t)}
              className={`px-3 py-1 ${tab === t ? "bg-zinc-100 text-zinc-900" : "text-zinc-400"}`}
            >
              {t}
            </button>
          ))}
        </div>
      }
    >
      <p className="mb-3 text-xs text-zinc-500">
        {bytes} bytes {tab === "query" ? "sent" : "received"} over UDP
        {tab === "response" && result.timing.rtt_ms != null && ` · ${result.timing.rtt_ms} ms round trip`}
        {tab === "response" && result.timing.rtt_ms == null && " · served from cache"}
      </p>
      <HexDump packet={packet} />
      <div className="mt-3 flex flex-wrap gap-3 text-xs">
        {SECTIONS.map((s) => (
          <span key={s} className="flex items-center gap-1.5 text-zinc-400">
            <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: sectionColor(s) }} />
            {s}
          </span>
        ))}
      </div>
    </Card>
  );
}
```

- [ ] **Step 2: Wire into `page.tsx`**

Add `import { PacketInspector } from "@/components/PacketInspector";` and replace `{/* Task 16: PacketInspector goes here */}` with `<PacketInspector result={state.result} />`.

- [ ] **Step 3: Verify and commit**

`npm run typecheck && npm run lint && npm run build` clean. In the browser: the Response tab of `www.microsoft.com` shows amber header bytes, sky question bytes, emerald answer bytes; hovering `c0 0c` at the start of the first answer shows `answer › NAME = → 0x0c (www.microsoft.com)`; the Query tab is 12 + QNAME + 4 bytes. Page is usable at 400px width (hex dump scrolls horizontally inside its box, page body does not).

```bash
git add dns-resolver-app/frontend
git commit -m "feat(frontend): annotated packet inspector with hover field labels

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 17: Frontend Dockerfile

**Files:**
- Create: `frontend/Dockerfile`, `frontend/.dockerignore`

- [ ] **Step 1: Write `frontend/.dockerignore`**

```
node_modules
.next
.git
*.md
```

- [ ] **Step 2: Write `frontend/Dockerfile`**

```dockerfile
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
USER nextjs
EXPOSE 3000
# API_URL is read at request time by src/app/api/[...path]/route.ts
CMD ["node", "server.js"]
```

If `public/` is empty after deleting the SVGs, add an empty `frontend/public/.gitkeep` so the `COPY` line has something to copy.

- [ ] **Step 3: Build and smoke-run**

From `dns-resolver-app/`:
```bash
docker build -t dns-frontend ./frontend
docker run --rm -d --name dns-frontend-test -p 3000:3000 -e API_URL=http://host.docker.internal:8000 dns-frontend
sleep 3
curl -s localhost:3000 | grep -o "DNS Resolver" | head -1
docker rm -f dns-frontend-test
```
Expected: `DNS Resolver`.

- [ ] **Step 4: Commit**

```bash
git add dns-resolver-app/frontend
git commit -m "build(frontend): standalone Next.js Dockerfile

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 18: docker-compose, README, end-to-end verification, push

**Files:**
- Create: `docker-compose.yml`, `README.md`

- [ ] **Step 1: Write `dns-resolver-app/docker-compose.yml`**

```yaml
services:
  backend:
    build: ./backend
    ports:
      - "8000:8000" # published so http://localhost:8000/docs is reachable during the demo
    environment:
      DNS_LOG_LEVEL: INFO
      DNS_DEFAULT_TIMEOUT: "5"
    restart: unless-stopped

  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    environment:
      API_URL: http://backend:8000
    depends_on:
      backend:
        condition: service_healthy
    restart: unless-stopped
```

- [ ] **Step 2: Write `dns-resolver-app/README.md`**

````markdown
# DNS Resolver App

A web front end for the raw-socket DNS client written for **CS3001 Computer Networks, Assignment 1**
(FAST-NUCES Karachi). The command-line submission lives one directory up in
[`../assignment.py`](../assignment.py); this app reuses its packet-building and parsing logic,
fixes the bugs found while testing it, and adds three teaching aids:

- **Annotated packet inspector** — every byte of the query and the response, coloured by section
  and labelled by field on hover (header → question → answer → authority → additional).
- **TTL-aware cache** — answers are cached for `min(TTL)`; the UI shows HIT / MISS / BYPASS and
  counts the remaining TTL down, exactly like a caching stub resolver.
- **Round-trip time** — measured around the UDP exchange.

No resolver library is used anywhere. Queries are built with `struct.pack`, sent with a UDP socket
to port 53, and parsed with `struct.unpack` — see `backend/app/dns/protocol.py`.

## Run it

```bash
docker compose up --build
```

- UI: http://localhost:3000
- API docs (Swagger): http://localhost:8000/docs

Try `google.com`, `www.microsoft.com` (CNAME chain), a `.edu`/`.org` domain, and a name that does
not exist (NXDOMAIN → SOA in the Authority section). Resolve the same name twice to see a cache HIT.

## Run without Docker

```bash
# backend
cd backend && uv sync && uv run uvicorn app.main:app --port 8000
# frontend (new shell)
cd frontend && npm install && npm run dev      # proxies /api/* to http://localhost:8000
```

## Tests

```bash
cd backend && uv run pytest            # add --run-network to also hit 8.8.8.8
cd frontend && npm test && npm run typecheck && npm run lint
```

## How the CLI maps onto the backend

| `assignment.py` (CLI) | `backend/app/dns/…` | What changed |
|---|---|---|
| `buildHeader` | `protocol.build_header` | same `struct.pack("!HHHHHH", …)` |
| `QNAME` | `protocol.encode_qname` | rejects empty / >63-byte labels |
| `QTYPE`, `QCLASS` | `QTYPE_A`, `QTYPE_AAAA`, `QCLASS_IN` | AAAA is 28, not 0 |
| `buildQuery` | `protocol.build_query` | takes a qtype |
| `parseHeader`, `getRCODE`, `typeRCODE` | `protocol.parse_header`, `Flags` | all flag bits decoded |
| `parseAnswers` (fixed 16-byte records) | `protocol.parse_record` / `parse_response` | walks by RDLENGTH, follows compression pointers, honours ANCOUNT/NSCOUNT/ARCOUNT |
| `handleQuery` | `transport.send_query` | checks source address + transaction ID, measures RTT, maps `OSError` |
| — | `cache.TtlCache` | new |

### Bugs in the CLI that the backend fixes

1. **CNAME answers** — the CLI assumed every answer was 16 bytes, so `www.microsoft.com` printed
   garbage after the CNAME. Records are now advanced by `RDLENGTH`.
2. **ANCOUNT ignored** — a NOERROR response with zero answers had its Authority SOA parsed as an answer.
3. **Transaction ID / QR never checked** — replies are now matched to the query.
4. **Crash on a bad server address** — `socket.gaierror`/`OSError` are caught and reported.

## API

`POST /api/v1/resolve` — `{"domain": "www.example.com", "server": "8.8.8.8", "qtype": "A", "timeout": 5, "bypass_cache": false}`
→ header, question, answers/authority/additional, `resolved_ips`, `timing.rtt_ms`, `cache.status`,
and both packets as hex with byte-range annotations. Non-2xx responses are
`{"error": "<code>", "detail": "<message>"}` with codes `validation_error` (422), `timeout` (504),
`malformed_response` (502), `network_error` (503).

`DELETE /api/v1/cache` — clears the cache. `GET /health` — liveness + cache size.

## Notes

- The backend runs one uvicorn worker on purpose: the cache is in-process.
- Not implemented (out of scope): TCP fallback on `TC=1`, EDNS0, DNSSEC validation, negative caching.

## Screenshots for the report

Capture, for each of at least three domains: the form (domain + server), the status strip (RCODE,
cache, RTT, ID), the Answer table with TTLs, and the Response tab of the packet inspector.
````

- [ ] **Step 3: Full end-to-end verification**

From `dns-resolver-app/`:
```bash
docker compose up --build -d
docker compose ps
```
Expected: both services `running`, backend `(healthy)`. Then:
```bash
curl -s -X POST localhost:3000/api/v1/resolve -H "content-type: application/json" -d '{"domain":"www.microsoft.com","server":"8.8.8.8","qtype":"A","bypass_cache":false}' | python -c "import json,sys; d=json.load(sys.stdin); print(d['cache']['status'], d['header']['flags']['rcode_name'], [a['type'] for a in d['answers']], d['resolved_ips'])"
curl -s -X POST localhost:3000/api/v1/resolve -H "content-type: application/json" -d '{"domain":"www.microsoft.com","server":"8.8.8.8","qtype":"A","bypass_cache":false}' | python -c "import json,sys; d=json.load(sys.stdin); print(d['cache'])"
curl -s -X POST localhost:3000/api/v1/resolve -H "content-type: application/json" -d '{"domain":"this-domain-does-not-exist-xyz123.com","server":"8.8.8.8","qtype":"A","bypass_cache":false}' | python -c "import json,sys; d=json.load(sys.stdin); print(d['header']['flags']['rcode_name'], d['authority'][0]['type'])"
curl -s -X POST localhost:3000/api/v1/resolve -H "content-type: application/json" -d '{"domain":"google.com","server":"192.0.2.1","qtype":"A","bypass_cache":false,"timeout":1}'
docker compose logs backend | tail -5
docker compose down
```
Expected, in order: `MISS NOERROR ['CNAME', ..., 'A'] ['…']`; `{'status': 'HIT', 'ttl_remaining': N}`; `NXDOMAIN SOA`; `{"error":"timeout","detail":"No response from 192.0.2.1:53 within 1s"}`; backend log lines like `resolve domain=www.microsoft.com qtype=A server=8.8.8.8 rcode=NOERROR cache=MISS rtt_ms=…`. Then open `http://localhost:3000` in a browser and walk through the four lookups above for the report screenshots.

- [ ] **Step 4: Run every automated check one last time**

```bash
cd backend && uv run pytest && uv run ruff check . && uv run ruff format --check . && cd ..
cd frontend && npm test && npm run typecheck && npm run lint && cd ..
```
Expected: all green.

- [ ] **Step 5: Commit and push**

From the git root:
```bash
git add dns-resolver-app
git commit -m "feat: docker-compose and README for the DNS resolver app

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
git push origin main
```

---

## Self-review notes

- **Spec coverage:** §4.2 build/parse → Tasks 2–5; §4.3 transport → Task 6; §4.4 cache → Task 7; §4.5 service + query spans → Task 9; §4.6 API/errors + §4.7 config/logging → Tasks 8, 10; §5 frontend (proxy, form, status, cards, inspector, error card) → Tasks 12–16; §6 Docker → Tasks 11, 17, 18; §7 tests → each task, network-marked tests exist via the `--run-network` option (no network tests are written because the fixtures already exercise real packets; the option remains for `capture.py`-style checks); §8 reuse table → README in Task 18.
- **Type consistency:** `Exchange(request, response, server, port, rtt_ms)` is used identically in Tasks 6, 7, 9; `RecordOut.rr_class` serialises as `class` (Task 8) and the frontend type reads `class` (Task 13); `Span` has the same five fields in Python and TypeScript; `CacheOut.status` literal matches `CacheStatus` in TS.
