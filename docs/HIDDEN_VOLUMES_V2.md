# Hidden Volumes v2 — Anchor + Directory Architecture

Status: **implemented** (experimental). The v2 slot key derivation (§1), the
passphrase-located anchor (§2), the directory format (§3), the whole-container
rewrite (§4), and the volume commands (§5) are all built and tested. Extends
the v1 primitive in [HIDDEN_VOLUMES.md](HIDDEN_VOLUMES.md). Read that first —
this document assumes its threat model, its framed-AEAD reuse, and its
"container is pure randomness, no header" invariant.

Implemented (`src/vault.c`, `include/vault.h`, wired in `src/main.c`):
`vault_slot_len`, `vault_v2_frame_key`, `vault_anchor_offset`, `vault_v2_seal`
/ `vault_v2_open`, `vault_dir_*`, the `vault_rewrite` engine, and the
`vault_volume_create` / `_add` / `_ls` / `_extract` / `_rm` commands, on a
general `crypto_hkdf_sha256`. Tested by KATs and round-trip/hostile-input unit
tests (`test_vault_v2_known_answer_vectors`, `test_vault_directory`) plus
integration tests in `tests/test.sh` — including a direct check that a mutating
write re-randomizes ≥99% of the container's bytes (the snapshot-diff property)
and that omitting a `--keep` passphrase destroys that volume.

v1 gave us a *coordinate-addressed* slot store: you supply
`(offset, capacity, scrypt-cost)` and the tool reads/writes there. It works,
it's fuzzed and CT-checked, but the container **cannot locate its own
contents** — every triple lives in your head. v2 adds the missing *addressing
layer* so a passphrase alone opens a whole **volume** (a named set of slots),
and changes the write model so a byte-level diff of two container snapshots
leaks nothing.

Two design commitments drive everything below:

1. **A passphrase must locate its own payload** — without planting any
   fixed-position, low-entropy structure an inspector could find *without*
   that passphrase. (The whole reason v1 punted on a directory.)
2. **Every write rewrites every byte** — so an adversary diffing an old backup
   against the current file sees uniform change, not "these 90 KB moved."
   (Closes v1's single biggest documented weakness, the two-snapshot attack.)

---

## 1. Slot format change: per-write nonce salt (v2 slots)

Commitment (2) forces a format change, and it's worth understanding why before
anything else.

A v1 slot key is `scrypt(passphrase, salt(offset, capacity))` — **fully
deterministic**. Frame nonces are deterministic counters. So a v1 slot's
ciphertext is a pure function of `(passphrase, offset, capacity, content)`:
re-encrypting identical content yields **identical bytes**. Under
write-whole-container that is a disaster — unchanged slots would keep their
old bytes while filler got re-randomized, so a snapshot diff would reveal
exactly which regions are slots (the unchanged ones). That *inverts* the leak
we're trying to close.

Fix: give every slot a random **nonce salt**, refreshed on every write, that
feeds the frame-key derivation.

```
v2 slot layout at its (offset, capacity):
  offset        size                       field
  ------        -------------------------  ------------------------------
  0             16                         nonce_salt (CSPRNG, fresh each write)
  16            ciphertext_len(capacity)   framed AEAD payload (§2.3 FORMAT.md)

frame_key = HKDF-SHA256(ikm  = scrypt(passphrase, coord_salt),
                        salt = nonce_salt,
                        info = "qsafe-vault-slot-v2",
                        L    = 32)
coord_salt = SHA-256("qsafe-vault-salt-v1" ‖ u64le(offset) ‖ u64le(capacity))[0:16]
                        (unchanged from v1 §3)
```

`nonce_salt` is 16 random-looking bytes at the slot's start, so it is
indistinguishable from the filler around it — no fingerprint. Refreshing it on
every write makes the slot's *entire* ciphertext change every write, which is
exactly what commitment (2) needs. It also buys a property v1 lacked for free:
two containers holding the same content under the same passphrase now differ
(semantic security across containers, not just within one).

**On-disk size:** `slot_len(capacity) = 16 + ciphertext_len(capacity)` where
`ciphertext_len` is v1's `capacity + 16 * (capacity / 65536 + 1)`.

---

## 2. The anchor: a passphrase locates its volume

A **volume** is anchored by a single v2 slot at a **passphrase-derived
offset** with a **fixed capacity and cost**, so the passphrase alone can find
and open it with no remembered coordinates.

```
container_size = the container file's length (public — it's just the file size)

loc_salt      = SHA-256("qsafe-vault-anchor-loc")[0:16]   # scrypt salt is a fixed
                                                          # 16 bytes, so the label
                                                          # is hashed, not used raw
anchor_ikm    = scrypt(passphrase, loc_salt, N=2^ANCHOR_LOG_N, r=8, p=1)
x8            = HKDF-SHA256(ikm  = anchor_ikm,
                           salt = (none — RFC 5869 default),
                           info = "qsafe-vault-anchor-v2" ‖ u64le(container_size),
                           L    = 8)
m             = container_size - slot_len(ANCHOR_CAPACITY) + 1
anchor_offset = (u64le(x8) * m) >> 64          # Lemire multiply-shift, NOT mod

ANCHOR_CAPACITY  = 4096            # holds a directory of up to 46 entries (§3)
ANCHOR_LOG_N     = 20             # fixed cost, so the passphrase alone opens it
```

The 8-byte HKDF output is read as a **little-endian** u64, then mapped into
`[0, m)` by **Lemire's multiply-shift** `(x * m) >> 64` — deliberately *not*
`x mod m`. `x` is secret-derived, and a 64-bit modulo is data-dependent in
timing on most CPUs, so `mod` would leak; a 128-bit multiply + shift is
constant-time. The mapping's bias is `<= m / 2^64` (negligible). `slot_len(4096)
= 4128`, so a container must be at least that many bytes to hold an anchor.

To open a container: compute `anchor_offset`, read a v2 slot at
`(anchor_offset, ANCHOR_CAPACITY)` under `ANCHOR_LOG_N`. If the GCM tag
verifies, this passphrase names a real volume and the slot's plaintext is its
**directory** (§3). If it fails, the reader emits the same generic "no data
here" as any v1 wrong-passphrase read — an empty container and a container
whose anchor you can't derive are indistinguishable.

The anchor offset is deterministic given `(passphrase, container_size)`, so it
sits at the same place across writes — but because *every* byte is
re-randomized on write (§4), a snapshot diff cannot pick the anchor out of the
uniform change. Stable location, unstable bytes, no leak.

**Cost note.** Every failed probe costs one `scrypt(ANCHOR_LOG_N = 2^20)`
(~1 GiB) plus one GCM open — deliberately, since that scrypt *is* the
guessing-cost wall for the whole volume (the anchor is the single point a
passphrase guess has to clear). One derivation per attempt, same as opening
any Qsafe key.

---

## 3. Directory format (anchor plaintext)

The anchor decrypts to a fixed `ANCHOR_CAPACITY`-byte plaintext: a small
header, a list of slot entries, then random padding to the full capacity. It
is *inside* the AEAD, so a version tag here is safe (it only exists after a
successful, authenticated decrypt) and doubles as a redundant sanity check on
top of the GCM tag.

```
offset  size    field
------  ------  ----------------------------------------
0       2       version (= 1)
2       2       entry_count (0..MAX_ENTRIES)
4       4       reserved (0)
8       E*88    entry[0..entry_count-1]              (see below)
...     var     random padding to ANCHOR_CAPACITY

entry (88 bytes):
  0     8       offset       (u64le — location of the data slot, v2)
  8     8       capacity     (u64le — its plaintext capacity)
  16    1       scrypt_log_n (u8   — this slot's KDF cost)
  17    1       flags        (u8)
  18    2       name_len     (u16le, <= 64)
  20    64      name         (name_len valid UTF-8 bytes; remainder 0)
  84    4       reserved
```

`MAX_ENTRIES = (ANCHOR_CAPACITY - 8) / 88 = 46` **per block**. A volume with
more than 46 slots chains additional directory blocks — see §3.1.

Data slots the directory lists are ordinary v2 slots (§1). Their
`(offset, capacity, cost)` now live in the encrypted directory, not your head
— but they are still keyed by the volume passphrase, so the directory only
tells you *where*, never *how to decrypt*: an attacker who somehow recovered a
directory plaintext without the passphrase (they can't — it's AEAD-sealed
under that passphrase) would learn locations of bytes they still cannot read.

**Where a data slot's content length lives (implementation decision).** The
directory entry deliberately does *not* carry a `content_len` field — a data
slot's real length stays *inside* the slot as a `u64le` prefix (`content_len ‖
content ‖ random_pad`, totalling `capacity`), exactly as v1
([HIDDEN_VOLUMES.md](HIDDEN_VOLUMES.md) §3) already does. This keeps the entry
at 46-per-block and makes the two slot kinds uniform at the crypto layer: the
generic v2 seal/open (`vault_v2_seal` / `vault_v2_open`) handle a plaintext
blob of *exactly* `capacity` bytes and nothing else; the "prefix + content +
pad" convention for data slots, and the self-describing directory for the
anchor, are both just choices of what those `capacity` bytes contain. That
generic primitive is also precisely what the whole-container rewrite (§4)
seals every preserved slot with.

**Implemented** (`src/vault.c`, `include/vault.h`): `vault_v2_seal` /
`vault_v2_open` (the generic exactly-capacity slot primitive),
`vault_dir_serialize` / `vault_dir_parse` (the latter bounds every
attacker-influenced field — version, `entry_count`, each `name_len`,
`capacity`, `offset`, `scrypt_log_n`), and `vault_dir_find` / `_add` /
`_remove`. Covered by `test_vault_directory` (serialization KAT, hostile-input
rejections, and an end-to-end seal → open → parse round-trip).

### 3.1 Overflow directories (chaining past 46 slots)

A volume with more than 46 slots chains directory blocks. The mechanism is
deliberately **not** a new header field — that would change the block format
and invalidate the frozen fixture and the KAT. Instead it reuses the existing
88-byte entry: an entry whose `flags` has `VAULT_ENTRY_FLAG_OVERFLOW` (bit 0)
set is **not a data slot** — its `offset` points at the next directory block (a
slot of capacity `ANCHOR_CAPACITY`), and its other fields are ignored except as
values the parser must still find in range. Because existing directories have
all-zero flags, a volume of ≤ 46 slots serializes byte-for-byte as before —
**no format-version bump, and the §8 fixture/KAT stay valid.**

- A **non-terminal** block spends one of its 46 records on the overflow pointer,
  so it carries **45** data slots; the **terminal** block carries up to 46.
- The chain is bounded to `VAULT_MAX_BLOCKS = 4` blocks →
  `45·3 + 46 = 181` slots per volume. (Need more? Use another volume.)
- On **read**, `vault_open_volume` follows the chain from the anchor,
  accumulating data entries into one flat in-memory directory and recording the
  overflow-block offsets; a malformed chain (two pointers in a block, a cycle
  past the bound, a missing terminal) fails closed like any bad decrypt.
- On **write**, the rewrite (§4) splits the flat directory back into blocks and
  seals each — the anchor at its passphrase-derived offset, overflow blocks at
  the offsets `add` auto-placed for them (they're ordinary `ANCHOR_CAPACITY`
  slots, sealed under the volume key, indistinguishable from filler).
- An overflow block's *location* leaks nothing: it is only revealed after
  decrypting the block that points to it, exactly like a data slot.

Covered by `test_vault_directory` (the flag round-trips through serialize/parse)
and, end to end, by an opt-in slow test that adds 48 slots across the boundary
(`QSAFE_SLOW_TESTS=1`, since each add is a whole-container rewrite).

---

## 4. Write-whole-container semantics, and the one hard tension

This is the design decision that needed resolving on paper, because the naive
version is subtly broken.

**The tension.** Commitment (2) says "every write re-randomizes every byte."
But you can only *preserve* a slot you can decrypt — and a container may hold
volumes under passphrases you didn't supply on this write. If a full rewrite
blindly re-randomizes everything except the volume you're writing, it
**destroys every other volume in the container.** This is precisely
VeraCrypt's documented outer-volume-clobbers-hidden-volume problem; it is not
avoidable at this layer, only managed.

**The resolution (VeraCrypt's model, made explicit).** A write is always a
whole-container operation that takes **every passphrase for every volume you
want to keep**. Regions claimed by a provided passphrase's directory are
preserved (re-sealed with fresh nonce salts); everything else becomes fresh
CSPRNG filler.

```
vault_rewrite(container, {(passphrase_i, mutation_i?)}):
  1. new_image <- CSPRNG bytes, length = container_size
  2. claimed <- []                              # occupied byte ranges
  3. for each provided passphrase P:
       a. a_off <- anchor_offset(P, container_size)
       b. D <- decrypt anchor at (a_off, ANCHOR_CAPACITY) from the OLD container
              (a brand-new volume starts with an empty directory D)
       c. if P is the mutation target: apply add/remove/replace to D
       d. for each entry e in D:
            pt <- decrypt OLD slot at (e.offset, e.capacity, e.cost)
            re-seal pt into new_image at (e.offset, e.capacity, e.cost)  # fresh nonce_salt
            claimed += [e.offset, e.offset + slot_len(e.capacity))
       e. re-seal the (updated) directory D into new_image at (a_off, ANCHOR_CAPACITY, ANCHOR_LOG_N)
          claimed += anchor range
  4. if any two ranges in `claimed` overlap -> ERROR (collision; refuse, change nothing)
  5. atomically replace container with new_image (temp file + rename)
```

Every byte in `new_image` is either a freshly-sealed slot (new nonce salt →
new bytes) or fresh filler, so a snapshot diff shows **uniform change** — the
adversary cannot distinguish "volume A was rewritten" from "the whole file was
re-randomized for anti-forensics," and cannot prove volume B was preserved, or
existed.

**What the user carries.** For a single volume this is trivial: one
passphrase, whole rewrite, done. For multiple volumes it is your job to pass
*all* the passphrases you want to survive a write — omit one and its volume is
gone. That burden is inherent to deniable multi-volume storage (VeraCrypt
imposes exactly the same "mount with protection" discipline) and there is no
cryptographic way around it: preserving bytes you can't decrypt is
preserving bytes, which is the leak.

**Collision.** Two passphrases can derive overlapping anchors, or one
volume's anchor can land on another's data slot. When you provide both
passphrases (step 4) it's detected and the write refuses. When you *don't*
hold the other passphrase, you cannot see its ranges and may re-randomize
them — same fundamental limitation as v1 slot collision, now also covering
anchors. Probability is birthday-over-container-size with ~4 KB anchors; for
any realistically sized container it is negligible, and it is documented, not
hidden.

---

## 5. Command surface

v1's low-level commands stay (they're the scriptable primitive and the fuzz
target): `vault init | write | read | footprint`. v2 adds a volume layer on
top (all **implemented**):

```
qsafe vault create   <container> --size <bytes>              # new container, one empty volume
qsafe vault create   <container> --keep <ppfile> [...]       # add a volume to an existing container
qsafe vault add      <container> <file> --name <s> --offset <n> --capacity <n>
qsafe vault ls       <container>                             # list the opened volume's directory
qsafe vault extract  <container> --name <s> <out>            # read one named slot
qsafe vault rm       <container> --name <s>                  # drop an entry, rewrite
qsafe vault passwd   <container> --new-passphrase-file <p>   # re-key a volume in place
```

`passwd` re-keys a volume without re-adding its slots: it reads the volume
under the current passphrase and re-seals every slot — and relocates the anchor
— under the new one, in a single whole-container rewrite. The old anchor's
bytes become fresh filler, so the old passphrase opens nothing afterward. Slot
*locations* don't change (only their keys do); the keyfile, if any, is
unchanged. `--keep` preserves other volumes as with any rewrite.

Every mutating command (`create`/`add`/`rm`) is internally a `vault_rewrite`
(§4). `--keep <ppfile>` (repeatable) supplies additional volume passphrases to
preserve on that rewrite. The passphrase for the *targeted* volume comes from
the usual `--passphrase-file` / `$QSAFE_PASSPHRASE` / prompt path, and
`--scrypt-cost` sets the KDF cost (its default is the fixed anchor cost; tests
use a cheap one).

**Placement.** `--offset` and `--capacity` are **optional** for `add`. With
neither, the slot is **auto-placed**: capacity defaults to an exact fit for the
content (`content_len + 8`, bounded below by the minimum), and the offset is
the lowest free gap that avoids every range the command can *see* — this
volume's anchor and slots, plus each `--keep` volume's. This can only avoid
*visible* volumes: a slot may still land on a volume whose passphrase wasn't
supplied (the same inherent limit as everything else — you must `--keep` what
you want protected). First-fit is safe for deniability because placement
location doesn't leak: every container byte is random-looking and a slot is
indistinguishable from filler regardless of where it sits. You can still pass
explicit `--offset`/`--capacity` to place by hand; either way the offset is
recorded in the directory, so `ls`/`extract` recover it and you never have to
remember it. The rewrite refuses (writing nothing) if any placed slot would
overlap another visible one. A second volume is created with `create --keep
<first>` (no `--size`).

---

## 5a. Optional keyfile (two-factor unlock)

Vault's reason to exist is coercion resistance, but a passphrase alone is a
single point of failure — compel the passphrase and it's over. A **keyfile**
adds a second factor: a file (a token on a USB stick, a specific image, any
bytes) that must be present *in addition to* the passphrase. Implemented and
**opt-in** via `--keyfile <path>`.

```
keyfile_key = SHA-256("qsafe-vault-keyfile-v1" ‖ file_contents)          # 32 bytes
```

`keyfile_key` is mixed into the HKDF `info` of **both** derivations:

- the **anchor location** (§2): `info = "qsafe-vault-anchor-v2" ‖ u64le(size)
  ‖ keyfile_key` — so without the keyfile the passphrase cannot even *find* the
  anchor, let alone open it;
- the **slot / anchor frame key** (§1): `info = "qsafe-vault-slot-v2" ‖
  keyfile_key`.

Both factors are therefore independently necessary: passphrase without keyfile,
or keyfile without passphrase, derives unrelated values and fails to open (same
generic "no data here" as any wrong secret). When no `--keyfile` is given,
nothing is appended and every derivation is **byte-identical** to the
no-keyfile case — so a keyfile is a pure, backward-compatible add-on, and the
existing KATs/fixtures (which use no keyfile) still hold.

Scope and caveats: the keyfile is a **container-level** factor — all volumes
and all `--keep` targets in one operation use the same `--keyfile`. Losing the
keyfile is losing the data (it's a second secret, with no recovery). The
keyfile's own protection is the file's secrecy/entropy: a low-entropy or
publicly-known keyfile adds little. It is *not* a substitute for a strong
passphrase — it multiplies, not replaces.

---

## 6. Threat-model deltas from v1

Everything in [HIDDEN_VOLUMES.md](HIDDEN_VOLUMES.md) §6 still holds. Changes:

| Scenario | v1 | v2 |
|:--|:--|:--|
| Two point-in-time snapshots of the container | **Broken** — diff reveals changed ranges | **Mitigated** — every write re-randomizes every byte; a diff is uniform. (Still assumes you actually *rewrote*; a container copied and never rewritten is just one snapshot.) |
| Remembering where your data is | Must recall every `(offset, capacity, cost)` | Passphrase alone opens the volume; only the passphrase (and the anchor's fixed cost) must be remembered |
| Multiple independent volumes, writing one | N/A (manual) | Writing preserves only volumes whose passphrase you supply via `--keep`; others are destroyed. Documented, VeraCrypt-equivalent burden. |
| Slot/anchor location collision | slot-vs-slot only | slot-vs-slot and anchor-vs-slot; detected when you hold both passphrases, else may clobber |
| Ciphertext determinism | same content+coords+pass → identical bytes | nonce salt makes every seal unique |
| Coerced passphrase | full compromise | with `--keyfile` (§5a), the passphrase alone can neither find nor open a volume — a second factor is required |

**Not changed / still out of scope:** the write-timing content-vs-padding side
channel (HIDDEN_VOLUMES.md §6 — now applies to the whole-container rewrite
too, since a rewrite's duration scales with total preserved content), and
everything under the "attacker on your machine" line in
[THREAT_MODEL.md](../THREAT_MODEL.md).

---

## 7. Open questions (decide before freezing v2)

- **Anchor cost vs. probe latency.** `ANCHOR_LOG_N = 2^20` makes a wrong
  passphrase cost ~1 GiB of scrypt. Good against guessing, but slow for an
  honest open. Tunable, but the cost can't be *stored* (fingerprint) — so it
  must be a fixed constant everyone agrees on, or itself remembered. Fixed
  constant is the current call.
- **~~`anchor_offset = x mod m` timing~~ — fixed.** The reduction now uses
  Lemire's constant-time multiply-shift `(x * m) >> 64` instead of a
  data-dependent `x mod m` (§2), so the anchor derivation no longer branches or
  divides on the secret-derived `x`. Residual mapping bias is `<= m / 2^64`,
  negligible. (Uses `unsigned __int128`, available on every 64-bit target Qsafe
  supports.)
- **~~Overflow directories~~ — done** (§3.1): the `flags` overflow bit chains
  up to `VAULT_MAX_BLOCKS` directory blocks (181 slots/volume). Raising the
  cap further is just a larger `VAULT_MAX_BLOCKS` (bounded by the in-memory
  directory struct's size).
- **Anchor capacity as a hiding parameter.** A fixed `ANCHOR_CAPACITY` is one
  more universal constant; fine for deniability (it's the same for everyone),
  but worth confirming it doesn't want to be size-class-dependent.

---

## 8. Assurance plan (mirrors what v1 already has)

**Done** (slot key + anchor, `test_vault_v2_known_answer_vectors`): KATs for
the v2 `frame_key` derivation and the `anchor_offset` pipeline, computed
independently in Python (`hashlib` + `cryptography`'s Scrypt/HKDF), plus an
RFC 5869 Test Case 1 vector pinning the new `crypto_hkdf_sha256` primitive to
the standard. Frozen values (all at scrypt `N=2^14` for speed):

- `anchor_loc_salt = SHA-256("qsafe-vault-anchor-loc")[0:16] = ba3bc735fa33627aaec7e4fb7915419c`
- `slot_len(4096) = 4128` (the anchor span)
- v2 frame key, `passphrase="vault-v2-kat-pass"`, coords `(0, 1048576)`,
  `nonce_salt = 00..0f`:
  `42b46cf77079791c9e0cc9057597759d88f7c41cb3571690984c4a95b6e8e2e2`
- anchor offset, `passphrase="vault-anchor-kat-pass"`,
  `container_size=10000000`: `5631317` (Lemire multiply-shift reduction)

**Done** (directory + v2 slot I/O, `test_vault_directory`): a serialization
KAT over the deterministic header+entries region (hashed, since the padding is
random) computed independently in Python; hostile-input rejections for the
directory parser (wrong version, over-max `entry_count`, over-max `name_len`,
out-of-range `scrypt_log_n`, sub-minimum `capacity`); `find`/`add`/`remove`
behavior; and an end-to-end `serialize → vault_v2_seal → vault_v2_open →
parse` round-trip, including that resealing the same directory yields different
ciphertext (the per-write nonce salt) and that a wrong passphrase fails to
open. All exercised under ASan/UBSan via `make test` in `hardening.yml`.

Frozen directory value: header+entries region SHA-256 for a 2-entry directory
(`decoy` at `(140048, 100000, log_n 20)`, `hidden` at `(500000, 50000,
log_n 14)`) = `c3d724acf8b88fdbf90d78d5c5c81274f1ea039177c116c008ce206e327f4b34`.

**Done** (whole-container rewrite + commands, `tests/test.sh`): create → add →
ls → extract → rm round-trips (one and two volumes); wrong-passphrase
rejection; overlap-collision refusal (nothing written); the **snapshot-diff
invariant** tested directly — a mutating write must re-randomize ≥99% of the
container's bytes (measured ~99.6%, i.e. `1 − 1/256`, confirming whole-file
re-randomization rather than localized change); and the `--keep` semantics —
`create --keep` preserves the first volume and its data, while a write that
omits a volume's passphrase destroys it. The full multi-volume flow also runs
clean under AddressSanitizer/UBSan.

**Done** (frozen fixture, `tests/fixtures/vault_v2/`): a checked-in two-volume
container (`container.bin`, volumes `volA`/`volB` at `--scrypt-cost 14`).
Because a v2 slot's per-write random nonce salt makes containers
non-reproducible, this pins decrypt *behavior* — both volumes must keep opening
and yielding their slots, and one volume's passphrase must not open the other's
— rather than exact bytes; `tests/test.sh` checks all three.

**Done** (directory-parser fuzzing, `tests/fuzz_vault_dir.c`): a libFuzzer
target over `vault_dir_parse` (the attacker-influenced fields once an anchor
decrypts), with a serialize→re-parse consistency check on valid inputs, wired
into `make fuzz-vault-dir`, `fuzz.yml`, the `hardening.yml` smoke run, and
`oss-fuzz/build.sh`. Smoke-tested locally via the `QSAFE_STANDALONE`
ASan/UBSan fallback (crafted boundary corpus + 1000 mutations, 0 crashes).

Overflow directories (§3.1) raise the per-volume cap from 46 to 181 slots.
