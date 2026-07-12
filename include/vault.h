#ifndef QSAFE_VAULT_H
#define QSAFE_VAULT_H

/* Deniable hidden-volume containers. See docs/HIDDEN_VOLUMES.md for the design
 * rationale (why this is a separate, symmetric-only format from QSAFE007) and
 * the full threat model / limitations. Experimental, v1. */

#include <stdint.h>
#include "crypto_utils.h"

/* Minimum bytes a slot's declared plaintext capacity must have room for: the
 * 8-byte content-length prefix plus at least one byte of content. */
#define VAULT_MIN_CAPACITY 9

/* Sanity upper bounds on --offset/--capacity (256 TiB each), rejected up
 * front. No real container is anywhere near this size; the bound exists so
 * vault_ciphertext_len(capacity) and offset + vault_ciphertext_len(capacity)
 * cannot wrap a 64-bit integer (2^48 + 16*(2^48/65536+1) is still ~2^48,
 * nowhere near 2^64) and silently pass a size check that should have failed. */
#define VAULT_MAX_OFFSET (1ULL << 48)
#define VAULT_MAX_CAPACITY (1ULL << 48)

/* Creates <path> containing `size` bytes of CSPRNG randomness. Fails (without
 * overwriting) if the file already exists unless force is set. */
crypto_error_t vault_init(const char *path, uint64_t size, int force);

/* Ciphertext bytes a slot of plaintext `capacity` occupies on disk:
 * capacity + 16 * (capacity / QSAFE_FRAME_SIZE + 1). Exposed for `vault
 * footprint` and for callers planning non-overlapping slot layouts. */
uint64_t vault_ciphertext_len(uint64_t capacity);

/* Encrypts input_path (a regular file; "-" for stdin) into a slot spanning
 * [offset, offset + vault_ciphertext_len(capacity)) of the container at path.
 * The container must already exist and be large enough. config supplies the
 * passphrase (config->passphrase) and optional scrypt cost override
 * (config->scrypt_n/r/p; 0 means the vault default, VAULT_DEFAULT_LOG_N). */
crypto_error_t vault_write(const char *path, uint64_t offset, uint64_t capacity,
                          const char *input_path, const crypto_config_t *config);

/* Attempts to recover the slot at [offset, offset + vault_ciphertext_len(capacity))
 * of the container at path using config->passphrase (and scrypt cost, as for
 * vault_write), writing the recovered content to output_path ("-" for stdout).
 * Returns CRYPTO_ERR_INTEGRITY — indistinguishably — for a wrong passphrase,
 * an unwritten range, or corrupted ciphertext: see docs/HIDDEN_VOLUMES.md §3. */
crypto_error_t vault_read(const char *path, uint64_t offset, uint64_t capacity,
                         const char *output_path, const crypto_config_t *config);

/* --- v2 building blocks: anchor + directory architecture ---
 * See docs/HIDDEN_VOLUMES_V2.md. These are the low-level derivations the
 * (upcoming) volume layer is built on, exposed now so they can be pinned by
 * known-answer tests independently of the higher-level commands. */

/* Bytes of fresh CSPRNG nonce salt prepended to every v2 slot, refreshed on
 * every write so a slot's whole ciphertext changes each time it is sealed. */
#define VAULT_NONCE_SALT_SIZE 16

/* Fixed capacity and scrypt cost (log2 N) of a volume's anchor slot, so a
 * passphrase alone can locate and open it with no remembered coordinates. */
#define VAULT_ANCHOR_CAPACITY 4096
#define VAULT_ANCHOR_LOG_N 20

/* On-disk length of a v2 slot: a 16-byte per-write nonce salt followed by the
 * framed AEAD payload (vault_ciphertext_len bytes). */
uint64_t vault_slot_len(uint64_t capacity);

/* Derives a v2 slot's 32-byte frame key from the passphrase (config->passphrase
 * + scrypt cost), the slot coordinates, and a per-write nonce salt of
 * VAULT_NONCE_SALT_SIZE bytes. Returns 1 on success, 0 on failure. key_out
 * receives AES_KEY_SIZE bytes. */
int vault_v2_frame_key(const crypto_config_t *config, uint64_t offset, uint64_t capacity,
                       const unsigned char *nonce_salt, unsigned char *key_out);

/* Derives the passphrase-located anchor offset for a container of the given
 * size, using scrypt cost (n, r, p). Production anchor opens pass
 * n = 1 << VAULT_ANCHOR_LOG_N; the cost is a parameter here so tests can use a
 * cheaper one. keyfile_key (32 bytes, or NULL) is mixed into the derivation
 * for the optional two-factor keyfile — NULL reproduces the no-keyfile offset.
 * Fails (CRYPTO_ERR_INVALID_INPUT) if the container is too small for an anchor. */
crypto_error_t vault_anchor_offset(const char *passphrase, uint64_t container_size,
                                   uint64_t n, uint32_t r, uint32_t p,
                                   const unsigned char *keyfile_key, uint64_t *offset_out);

/* Derives a 32-byte keyfile key from a file: SHA-256("qsafe-vault-keyfile-v1"
 * ‖ file_contents). The result is what a caller stores in
 * crypto_config_t.vault_keyfile_key. */
crypto_error_t vault_keyfile_from_file(const char *path, unsigned char out[32]);

/* Generic v2 slot seal/open: encrypt or recover a plaintext blob of *exactly*
 * `capacity` bytes at a slot. `slot` points at the slot's first byte (the
 * caller places it at container base + offset). `offset` is passed because it
 * (with capacity) derives the coordinate salt / frame key and is bound as AAD,
 * so a slot cannot be replayed into a different location. seal generates a
 * fresh nonce salt; open returns 1 only if the GCM tags all verify. The blob's
 * higher-level meaning (a data slot's content_len prefix + padding, or an
 * anchor's directory) is the caller's concern — this layer just seals bytes. */
int vault_v2_seal(unsigned char *slot, uint64_t offset, uint64_t capacity,
                  const crypto_config_t *config, const unsigned char *plaintext);
int vault_v2_open(const unsigned char *slot, uint64_t offset, uint64_t capacity,
                  const crypto_config_t *config, unsigned char *plaintext_out);

/* --- Volume directory (the anchor slot's plaintext; docs/HIDDEN_VOLUMES_V2.md §3) --- */

#define VAULT_DIR_VERSION   1
#define VAULT_DIR_HEADER    8                 /* version(2) + entry_count(2) + reserved(4) */
#define VAULT_ENTRY_SIZE    88
#define VAULT_MAX_NAME_LEN  64
#define VAULT_MAX_ENTRIES   ((VAULT_ANCHOR_CAPACITY - VAULT_DIR_HEADER) / VAULT_ENTRY_SIZE) /* 46, per block */

/* Overflow directories (docs/HIDDEN_VOLUMES_V2.md §3.1). A single block holds at
 * most VAULT_MAX_ENTRIES (46) records, but a volume can chain blocks: an entry
 * flagged VAULT_ENTRY_FLAG_OVERFLOW is not a data slot — its offset points at
 * the next directory block (a slot of capacity VAULT_ANCHOR_CAPACITY). A
 * non-terminal block spends one of its 46 records on that pointer, so it holds
 * 45 data records; the terminal block holds up to 46. The chain is bounded to
 * VAULT_MAX_BLOCKS. This adds no header field and no format-version bump — a
 * volume with <= 46 slots serializes byte-identically to before. */
#define VAULT_ENTRY_FLAG_OVERFLOW 0x01
#define VAULT_MAX_BLOCKS    4
#define VAULT_DATA_PER_INNER_BLOCK (VAULT_MAX_ENTRIES - 1) /* 45: one record is the overflow pointer */
#define VAULT_MAX_VOL_ENTRIES (VAULT_DATA_PER_INNER_BLOCK * (VAULT_MAX_BLOCKS - 1) + VAULT_MAX_ENTRIES) /* 181 */

/* One data-slot record. A data slot's real content length is not stored here —
 * it lives inside the slot (a v1-style u64 content_len prefix), so the
 * directory is only a location index. */
typedef struct {
    uint64_t offset;         /* the data slot's location in the container */
    uint64_t capacity;       /* its plaintext capacity */
    uint8_t  scrypt_log_n;   /* its KDF cost, log2(N), in [14, 22] */
    uint8_t  flags;
    uint16_t name_len;       /* <= VAULT_MAX_NAME_LEN */
    unsigned char name[VAULT_MAX_NAME_LEN];
} vault_entry_t;

/* In-memory view of a whole volume's directory: the *data* entries flattened
 * across all chained blocks, plus the offsets of any overflow blocks (block 0
 * is always the passphrase-located anchor and is not listed here). A volume
 * with <= 46 entries has noverflow == 0 and behaves exactly as a single block. */
typedef struct {
    uint16_t version;
    uint16_t entry_count;    /* data entries, <= VAULT_MAX_VOL_ENTRIES */
    vault_entry_t entries[VAULT_MAX_VOL_ENTRIES];
    uint64_t overflow_off[VAULT_MAX_BLOCKS - 1]; /* offsets of blocks 1..noverflow */
    int      noverflow;
} vault_dir_t;

/* Serialize a directory into an ANCHOR_CAPACITY-byte plaintext block: header,
 * packed entries, then random padding to the full capacity (so the padding is
 * indistinguishable from an unused slot's filler). Returns 1 on success, 0 if
 * entry_count exceeds VAULT_MAX_ENTRIES or the CSPRNG fails. */
int vault_dir_serialize(const vault_dir_t *dir, unsigned char *out /* [VAULT_ANCHOR_CAPACITY] */);

/* Parse and validate an ANCHOR_CAPACITY-byte block. This runs on
 * attacker-influenced bytes (anyone who can craft an anchor plaintext), so it
 * bounds every field: version, entry_count, each name_len, and each entry's
 * capacity/offset/cost. Returns 1 on a fully valid directory, 0 otherwise. */
int vault_dir_parse(const unsigned char *in /* [VAULT_ANCHOR_CAPACITY] */, vault_dir_t *dir);

/* Directory manipulation. find returns the entry index or -1; add appends
 * (rejecting a duplicate name or a full directory); remove drops a named entry
 * (compacting the list). Names compare as exact byte strings. */
int vault_dir_find(const vault_dir_t *dir, const char *name);
int vault_dir_add(vault_dir_t *dir, const vault_entry_t *entry);
int vault_dir_remove(vault_dir_t *dir, const char *name);

/* --- v2 volume commands (whole-container rewrite; docs/HIDDEN_VOLUMES_V2.md §4-5) ---
 *
 * Every mutating command below is a whole-container rewrite: the entire file
 * is re-randomized and each preserved slot re-sealed with a fresh nonce salt,
 * so a byte-level diff of two container snapshots shows uniform change. A
 * write preserves ONLY the volumes whose passphrase it is given — the target
 * (config->passphrase) plus any keep_passphrases — and re-randomizes
 * everything else, so omitting a volume's passphrase on a write destroys it
 * (the VeraCrypt outer-clobbers-hidden tension, §4). */

/* Create a volume. size > 0: a brand-new container of `size` bytes (fresh
 * randomness) with one empty volume under config->passphrase (refuses an
 * existing file unless force; keep_passphrases must be empty). size == 0: add
 * a new empty volume to the existing container, preserving the kept volumes. */
crypto_error_t vault_volume_create(const char *container, uint64_t size,
                                   const crypto_config_t *config, int force,
                                   const char *const *keep_passphrases, int n_keep);

/* Add `infile` as a named data slot in config's volume, preserving that
 * volume's existing slots and the kept volumes. have_offset/have_capacity say
 * whether offset/capacity were supplied: when have_offset is 0 the slot is
 * auto-placed in the first free gap among the visible volumes; when
 * have_capacity is 0 the capacity defaults to an exact fit for the content. */
crypto_error_t vault_volume_add(const char *container, const char *name, const char *infile,
                                uint64_t offset, int have_offset,
                                uint64_t capacity, int have_capacity, const crypto_config_t *config,
                                const char *const *keep_passphrases, int n_keep);

/* List config's volume directory on stdout. Read-only (no rewrite). */
crypto_error_t vault_volume_ls(const char *container, const crypto_config_t *config);

/* Extract a named data slot to outfile ("-" for stdout). Read-only. */
crypto_error_t vault_volume_extract(const char *container, const char *name,
                                    const char *outfile, const crypto_config_t *config);

/* Remove a named data slot from config's volume, preserving the rest and the
 * kept volumes. */
crypto_error_t vault_volume_rm(const char *container, const char *name,
                               const crypto_config_t *config,
                               const char *const *keep_passphrases, int n_keep);

/* Change a volume's passphrase in place: config carries the *current*
 * passphrase (and keyfile, which is unchanged), new_passphrase is the
 * replacement. Re-seals the volume's slots and relocates its anchor under the
 * new passphrase, preserving content and the kept volumes. */
crypto_error_t vault_volume_passwd(const char *container, const crypto_config_t *config,
                                   const char *new_passphrase,
                                   const char *const *keep_passphrases, int n_keep);

#endif /* QSAFE_VAULT_H */
