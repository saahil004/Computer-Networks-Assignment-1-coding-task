# DNS Query Program — Theory & Structure Recap

## 1. Big Picture

A DNS message (both query and response) has up to three sections, in this order:

```
[ Header ]    12 bytes, fixed size, always present
[ Question ]  the name/type being asked about, always present
[ Answer ]    the actual record(s) — only meaningful in a response
```

You **send**: Header + Question.
You **receive**: Header + Question (echoed back) + Answer.

---

## 2. Header (12 bytes = six 2-byte fields)

| Field | Size | Query value | Response meaning |
|---|---|---|---|
| ID | 2 bytes | any number you pick | server echoes it back — used to match response to request |
| Flags | 2 bytes | `0x0100` | see breakdown below |
| QDCOUNT | 2 bytes | `1` | number of questions |
| ANCOUNT | 2 bytes | `0` | number of answers (server fills this in) |
| NSCOUNT | 2 bytes | `0` | number of authority records |
| ARCOUNT | 2 bytes | `0` | number of additional records |

**Rule of thumb for a query:** only QDCOUNT is 1; everything else in the counts is 0, because you're asking, not answering.

### Flags — 16 individual bits packed together

Bit order: `QR · Opcode(4 bits) · AA · TC · RD · RA · Z · AD · CD · RCODE(4 bits)`

| Flag | Meaning | Set by |
|---|---|---|
| QR | 0=query, 1=response | either |
| Opcode | `0000` = standard query | either |
| AA | Authoritative Answer | server only |
| TC | Truncated (didn't fit in one packet) | server only |
| RD | Recursion Desired — "please fully resolve this for me" | **client sets to 1** |
| RA | Recursion Available — server confirms it recurses | server only |
| Z | reserved, always 0 | — |
| AD / CD | DNSSEC-related, ignore for this assignment | — |
| RCODE | result code (see below) | server only |

**Query flags value:** RD=1, everything else 0 → binary `0000 0001 0000 0000` → hex `0x0100` → decimal `256`.

**RCODE values (bottom 4 bits, response only):**
| Value | Meaning |
|---|---|
| 0 | No error (success) |
| 1 | Format error |
| 2 | Server failure |
| 3 | **Name Error (NXDOMAIN)** — domain doesn't exist |
| 5 | Refused |

To read RCODE from a parsed flags integer: `rcode = flags & 0x000F` (mask the last 4 bits).

---

## 3. Question Section

Sent as: **QNAME + QTYPE + QCLASS**

### QNAME — length-prefixed labels, no dots

DNS never sends literal dots. Each label (the parts between dots) is prefixed by a single byte giving its length, and the whole name ends with a zero byte.

Example: `"mail.google.com"` →
```
[4] m a i l [6] g o o g l e [3] c o m [0]
```
= `b'\x04mail\x06google\x03com\x00'` (17 bytes total)

### QTYPE (2 bytes)
`1` = A record (IPv4 address) — the only type this assignment needs.

### QCLASS (2 bytes)
`1` = IN (Internet). Note: QTYPE answers "what kind of record," QCLASS answers "what network" — different questions, same value by coincidence.

---

## 4. Answer Section (response only)

Comes after the header + question in the response. Structure per record:

| Field | Size | Meaning |
|---|---|---|
| NAME | usually 2 bytes (compressed) | which name this record answers for |
| TYPE | 2 bytes | `1` = A record |
| CLASS | 2 bytes | `1` = IN |
| TTL | 4 bytes | seconds this answer can be cached before re-querying |
| RDLENGTH | 2 bytes | length in bytes of RDATA that follows |
| RDATA | RDLENGTH bytes | actual data — for an A record, 4 raw bytes = the IPv4 address |

### Message Compression (pointers)

Instead of repeating a name already written earlier in the packet (e.g. in the Question section), DNS uses a 2-byte **pointer**. A byte starting with binary `11` (i.e. `0xC0` or higher) signals "this is a pointer, not a length byte." The remaining 14 bits give a byte **offset** from the start of the whole message, telling you where the real name is.

Common example: `0xC0 0x0C` → offset `12` → right after the 12-byte header, i.e. the start of the Question section's QNAME.

### Converting RDATA to an IP address

RDATA for an A record is exactly 4 raw bytes, each 0–255. Read them in order and join with dots:
```
bytes: 93, 184, 216, 34  →  "93.184.216.34"
```

### TTL and caching

TTL = how many seconds an answer stays valid before it must be re-queried. Example: TTL=300 (5 minutes) means a lookup 2 minutes later can reuse the cached answer, but a lookup 10 minutes later must ask the server again. This is the mechanism behind local DNS caching covered in class.

---

## 5. Parsing Order for a Response (recommended)

1. **Check ID** matches the ID you sent — confirms this response actually corresponds to your query (UDP has no built-in guarantee of this).
2. **Check RCODE** (bottom 4 bits of flags) — if nonzero, report the specific error (e.g. NXDOMAIN) and stop before touching the Answer section.
3. **Check ANCOUNT** — if 0, there's nothing to parse in the Answer section even if RCODE was success.
4. **Skip the Question section** — you already know its contents since you wrote it; just need to know its byte length to find where the Answer section starts.
5. **Parse each Answer record** — NAME (likely a pointer), TYPE, CLASS, TTL, RDLENGTH, RDATA → convert RDATA to a dotted IP string.

---

## 6. Python Tools Used

### `struct` module (standard library, no install needed)

Converts between Python values and exact raw byte layouts — necessary because DNS requires fixed-size fields in a specific byte order.

**Format codes:**
| Code | Size | Type |
|---|---|---|
| `B` | 1 byte | unsigned char (0–255) |
| `H` | 2 bytes | unsigned short (0–65535) |
| `I` | 4 bytes | unsigned int |

**Byte order prefix:** always use `!` (network/big-endian byte order) for DNS.

**`struct.pack(format, values...)`** — values → bytes. One format letter per value, in order.
```python
struct.pack("!HHHHHH", id, flags, qd, an, ns, ar)  # 6 values in, 12 bytes out
```

**`struct.unpack(format, bytes)`** — bytes → tuple of values (reverse direction).
```python
id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
```

### `socket` module (standard library)

Used for UDP communication:
```python
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket
sock.settimeout(seconds)   # avoid hanging forever on no response
sock.sendto(query_bytes, (dns_server_ip, 53))
response, addr = sock.recvfrom(512)  # DNS responses are typically ≤512 bytes over UDP
```

---

## 7. Functions Built So Far

```python
import struct
import socket

def buildHeader(id, qd=1, an=0, ns=0, ar=0):
    flags = 0x0100  # RD=1, everything else 0
    data = struct.pack("!HHHHHH", id, flags, qd, an, ns, ar)
    return data

def parseHeader(data):
    id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    return id, flags, qd, an, ns, ar

def QNAME(domain):
    arr = domain.split('.')
    qname = b""
    for x in arr:
        qname += struct.pack("!B", len(x)) + x.encode()
    qname += struct.pack("!B", 0)
    return qname
```

## 8. Still To Build

- `buildQuestion(domain)` — append QTYPE(1) + QCLASS(1) after QNAME bytes
- Full `build_query(domain, id)` — combines header + question into one packet
- UDP send/receive logic with timeout handling
- `parse_answer(data, offset)` — handle name compression pointers, extract TYPE/CLASS/TTL/RDLENGTH/RDATA
- IP address formatting from 4 raw RDATA bytes
- Main loop: accept domain from user repeatedly, handle NXDOMAIN/timeout/malformed responses gracefully
