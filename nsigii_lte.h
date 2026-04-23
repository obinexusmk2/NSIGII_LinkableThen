/*
 * nsigii_lte.h — Linkable Then Executable (LTE) Protocol
 * OBINexus SDK | MMUKO OS Design and Technology LLC
 * Author: Nnamdi Michael Okpala
 *
 * PRINCIPLE: An artifact must be LINKABLE first.
 * Only after link verification passes can it be EXECUTED.
 * Execution of an unlinked artifact is a constitutional violation.
 *
 * States:
 *   UNLINKED   → artifact exists but has not been verified
 *   LINKED     → artifact is verified and ready for execution
 *   EXECUTING  → artifact is running under constitutional consent
 *   REJECTED   → artifact failed link verification, cannot execute
 */

#ifndef NSIGII_LTE_H
#define NSIGII_LTE_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* ─── Constants ───────────────────────────────────────────────────────────── */

#define LTE_HASH_SIZE     32      /* SHA-256 = 32 bytes               */
#define LTE_HASH_HEX_SIZE 65      /* 64 hex chars + null terminator   */
#define LTE_NAME_SIZE     128     /* artifact name max length          */
#define LTE_MAX_CHAIN     2048    /* max linked artifacts in a chain   */

/* ─── LTE State Machine ───────────────────────────────────────────────────── */

typedef enum {
    LTE_UNLINKED  = 0,
    LTE_LINKED    = 1,
    LTE_EXECUTING = 2,
    LTE_REJECTED  = 3
} LTEState;

/* ─── Artifact ────────────────────────────────────────────────────────────── */

typedef struct {
    char     name[LTE_NAME_SIZE];        /* artifact identifier             */
    uint8_t  content_hash[LTE_HASH_SIZE];/* SHA-256 of artifact content     */
    char     content_hex[LTE_HASH_HEX_SIZE]; /* hex string of content_hash  */
    uint8_t  link_hash[LTE_HASH_SIZE];   /* SHA-256 of name + content_hash  */
    char     link_hex[LTE_HASH_HEX_SIZE];/* hex string of link_hash         */
    uint8_t  prev_hash[LTE_HASH_SIZE];   /* previous artifact in chain      */
    char     prev_hex[LTE_HASH_HEX_SIZE];/* hex string of prev_hash         */
    int64_t  timestamp;                  /* Unix ms at link time            */
    LTEState state;                      /* current LTE state               */
} LTEArtifact;

/* ─── Chain ───────────────────────────────────────────────────────────────── */

typedef struct {
    LTEArtifact artifacts[LTE_MAX_CHAIN];
    size_t      count;
} LTEChain;

/* ─── Result ──────────────────────────────────────────────────────────────── */

typedef enum {
    LTE_OK               = 0,
    LTE_ERR_UNLINKED     = 1,  /* tried to execute before linking        */
    LTE_ERR_HASH_MISMATCH= 2,  /* link hash does not match recomputation */
    LTE_ERR_CHAIN_BROKEN = 3,  /* prev_hash does not match prior artifact*/
    LTE_ERR_REJECTED     = 4,  /* artifact was previously rejected       */
    LTE_ERR_NULL         = 5,  /* null pointer passed                    */
    LTE_ERR_OVERFLOW     = 6   /* chain is full                          */
} LTEResult;

/* ─── API ─────────────────────────────────────────────────────────────────── */

/*
 * lte_sha256 — compute SHA-256 of data, store in out (32 bytes)
 * Pure C implementation — no external crypto dependency.
 */
void lte_sha256(const uint8_t *data, size_t len, uint8_t out[LTE_HASH_SIZE]);

/* Convert 32-byte hash to 64-char hex string (null-terminated) */
void lte_hex(const uint8_t hash[LTE_HASH_SIZE], char hex[LTE_HASH_HEX_SIZE]);

/*
 * lte_link — perform the LINK step on an artifact.
 *
 * Computes:
 *   content_hash = SHA-256(content, content_len)
 *   link_hash    = SHA-256(name || content_hash || prev_hash || timestamp)
 *
 * Transitions state: UNLINKED → LINKED
 * Must be called before lte_execute.
 */
LTEResult lte_link(LTEArtifact *artifact,
                   const char  *name,
                   const uint8_t *content,
                   size_t        content_len,
                   const uint8_t prev_hash[LTE_HASH_SIZE]);

/*
 * lte_verify — recompute link_hash and confirm it matches stored value.
 * Does NOT change state. Returns LTE_OK if hash matches.
 */
LTEResult lte_verify(const LTEArtifact *artifact,
                     const uint8_t *content,
                     size_t         content_len);

/*
 * lte_execute — attempt to execute the artifact.
 *
 * Constitutional rule: artifact MUST be in LTE_LINKED state.
 * If not linked → state set to LTE_REJECTED, returns LTE_ERR_UNLINKED.
 * If linked     → state set to LTE_EXECUTING, returns LTE_OK.
 */
LTEResult lte_execute(LTEArtifact *artifact);

/*
 * lte_chain_append — add a linked artifact to a chain.
 * Validates that artifact->prev_hash matches the last artifact in chain.
 */
LTEResult lte_chain_append(LTEChain *chain, const LTEArtifact *artifact);

/*
 * lte_chain_verify — verify the entire chain is intact.
 * Checks every link_hash and prev_hash linkage.
 */
LTEResult lte_chain_verify(const LTEChain *chain,
                            const uint8_t *contents[],
                            const size_t   content_lens[]);

/* State label string */
const char *lte_state_label(LTEState state);

/* Result label string */
const char *lte_result_label(LTEResult result);

#endif /* NSIGII_LTE_H */
