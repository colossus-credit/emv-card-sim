# File System Architecture

The applet simulates an EMV file system without allocating real EFs on the JavaCard. All record data lives in the `EmvTag` linked list and is assembled on demand at READ RECORD time via `RecordTemplate`.

## How It Works

A personalization bureau (or the Python tool) sends three types of STORE DATA commands:

### 1. DGI 0062 — File Structure Declaration (optional)

Declares SFI-indexed elementary files per CPS Annex A.5 Table A-27. Each FCP (tag `62`) contains:

| Tag | Meaning | Required |
|-----|---------|----------|
| `80` | Data bytes in file | M |
| `82` | File descriptor byte | M |
| `88` | Short File Identifier (01-1E) | M |
| `8C` | Security attributes | O |

The applet validates the FCP structure (returns `6A80` on malformed data) but does **not** allocate physical EFs. File simulation is permitted by CPS v2.0 SS5.3.

### 2. DGI 01xx-1Exx — Record Data

The DGI encodes the target location: high byte = SFI, low byte = record number. For example, DGI `0101` = SFI 1, Record 1.

The payload is a TLV stream optionally wrapped in tag `70`:

```
70 <len>
  5A 08 <PAN bytes>          -- tag 5A
  5F24 03 <expiry bytes>     -- tag 5F24
  ...
```

On receipt, the applet:

1. Strips the `70` wrapper if present
2. Parses each inner TLV
3. Stores each tag's value in `EmvTag.setTag()` (creates or updates the node)
4. Collects direct `EmvTag` references into a `RecordTemplate` keyed by `(recordNo << 8) | (SFI << 3)`

### 3. READ RECORD — O(k) Response

When the terminal issues READ RECORD, the applet:

1. Looks up the `RecordTemplate` by the canonical key derived from P1 (record number) and P2 (SFI)
2. Calls `template.expandToArray()` which serializes each referenced EmvTag's **current** value

Because RecordTemplate stores object pointers (not tag IDs), dynamic tags that are mutated at transaction time (e.g., `9F6E` updated during GPO) are automatically reflected — `setData()` modifies the EmvTag node in place and the stored reference stays valid.

## Data Flow

```
Bureau / Python tool                    JavaCard Applet
─────────────────                       ───────────────
STORE DATA DGI 0062                     validateDgi0062() — validate FCP, no allocation
STORE DATA DGI 0101  ──────────────►    processOneDgi() → parse TLV → EmvTag.setTag()
  70 <len> 5A 08 ... 5F24 03 ...                           → RecordTemplate.setTemplate()
STORE DATA DGI 0102  ──────────────►    (same)
STORE DATA P1=80 DGI 7FFF              commitPersonalization() → PERSO_DONE

Terminal
───────
READ RECORD P1=01, P2=0C  ────────►    RecordTemplate.findTemplate(key)
                           ◄────────    template.expandToArray() → 70 <tlv stream>
```

## Key Classes

| Class | Role |
|-------|------|
| `EmvTag` | Doubly-linked list storing tag ID → value. `setData()` mutates in place. |
| `RecordTemplate` | Static linked list mapping record keys → `EmvTag[]` references. O(k) expansion. |
| `TagTemplate` | Stores 2-byte tag ID lists for single-call responses (GPO, GENAC, SELECT). O(k*n) expansion — acceptable for k=3-5 tags. |
