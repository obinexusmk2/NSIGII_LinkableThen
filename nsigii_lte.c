/*
 * nsigii_lte.c — Linkable Then Executable (LTE) Implementation
 * OBINexus SDK | MMUKO OS Design and Technology LLC
 * Author: Nnamdi Michael Okpala
 */

#include "nsigii_lte.h"

#include <string.h>
#include <stdio.h>
#include <time.h>

/* ─── SHA-256 (pure C, no external deps) ─────────────────────────────────── */

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define CH(e,f,g)   (((e)&(f))^(~(e)&(g)))
#define MAJ(a,b,c)  (((a)&(b))^((a)&(c))^((b)&(c)))
#define EP0(a)      (ROTR32(a,2)^ROTR32(a,13)^ROTR32(a,22))
#define EP1(e)      (ROTR32(e,6)^ROTR32(e,11)^ROTR32(e,25))
#define SIG0(x)     (ROTR32(x,7)^ROTR32(x,18)^((x)>>3))
#define SIG1(x)     (ROTR32(x,17)^ROTR32(x,19)^((x)>>10))

void lte_sha256(const uint8_t *data, size_t len, uint8_t out[LTE_HASH_SIZE]) {
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };

    /* build padded message */
    size_t total = ((len + 8) / 64 + 1) * 64;
    uint8_t *msg = (uint8_t *)__builtin_alloca(total);
    memset(msg, 0, total);
    memcpy(msg, data, len);
    msg[len] = 0x80;
    uint64_t bit_len = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++)
        msg[total - 1 - i] = (uint8_t)(bit_len >> (8 * i));

    /* process each 64-byte block */
    for (size_t i = 0; i < total; i += 64) {
        uint32_t w[64];
        for (int j = 0; j < 16; j++) {
            w[j] = ((uint32_t)msg[i+j*4]   << 24) |
                   ((uint32_t)msg[i+j*4+1] << 16) |
                   ((uint32_t)msg[i+j*4+2] <<  8) |
                   ((uint32_t)msg[i+j*4+3]);
        }
        for (int j = 16; j < 64; j++)
            w[j] = SIG1(w[j-2]) + w[j-7] + SIG0(w[j-15]) + w[j-16];

        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],
                 e=h[4],f=h[5],g=h[6],hh=h[7];

        for (int j = 0; j < 64; j++) {
            uint32_t t1 = hh + EP1(e) + CH(e,f,g) + K[j] + w[j];
            uint32_t t2 = EP0(a) + MAJ(a,b,c);
            hh=g; g=f; f=e; e=d+t1;
            d=c;  c=b; b=a; a=t1+t2;
        }

        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(h[i] >> 24);
        out[i*4+1] = (uint8_t)(h[i] >> 16);
        out[i*4+2] = (uint8_t)(h[i] >>  8);
        out[i*4+3] = (uint8_t)(h[i]);
    }
}

void lte_hex(const uint8_t hash[LTE_HASH_SIZE], char hex[LTE_HASH_HEX_SIZE]) {
    static const char tbl[] = "0123456789abcdef";
    for (int i = 0; i < LTE_HASH_SIZE; i++) {
        hex[i*2]   = tbl[(hash[i] >> 4) & 0xf];
        hex[i*2+1] = tbl[hash[i] & 0xf];
    }
    hex[LTE_HASH_HEX_SIZE - 1] = '\0';
}

/* ─── Labels ──────────────────────────────────────────────────────────────── */

const char *lte_state_label(LTEState state) {
    switch (state) {
        case LTE_UNLINKED:  return "UNLINKED";
        case LTE_LINKED:    return "LINKED";
        case LTE_EXECUTING: return "EXECUTING";
        case LTE_REJECTED:  return "REJECTED";
        default:            return "UNKNOWN";
    }
}

const char *lte_result_label(LTEResult result) {
    switch (result) {
        case LTE_OK:                return "OK";
        case LTE_ERR_UNLINKED:      return "ERR_UNLINKED";
        case LTE_ERR_HASH_MISMATCH: return "ERR_HASH_MISMATCH";
        case LTE_ERR_CHAIN_BROKEN:  return "ERR_CHAIN_BROKEN";
        case LTE_ERR_REJECTED:      return "ERR_REJECTED";
        case LTE_ERR_NULL:          return "ERR_NULL";
        case LTE_ERR_OVERFLOW:      return "ERR_OVERFLOW";
        default:                    return "ERR_UNKNOWN";
    }
}

/* ─── Link ────────────────────────────────────────────────────────────────── */

LTEResult lte_link(LTEArtifact *artifact,
                   const char  *name,
                   const uint8_t *content,
                   size_t        content_len,
                   const uint8_t prev_hash[LTE_HASH_SIZE]) {
    if (!artifact || !name || !content) return LTE_ERR_NULL;

    /* store name */
    strncpy(artifact->name, name, LTE_NAME_SIZE - 1);
    artifact->name[LTE_NAME_SIZE - 1] = '\0';

    /* content_hash = SHA-256(content) */
    lte_sha256(content, content_len, artifact->content_hash);
    lte_hex(artifact->content_hash, artifact->content_hex);

    /* store prev_hash */
    if (prev_hash)
        memcpy(artifact->prev_hash, prev_hash, LTE_HASH_SIZE);
    else
        memset(artifact->prev_hash, 0, LTE_HASH_SIZE);
    lte_hex(artifact->prev_hash, artifact->prev_hex);

    /* timestamp */
    artifact->timestamp = (int64_t)time(NULL) * 1000;

    /*
     * link_hash = SHA-256(name || content_hash || prev_hash || timestamp)
     * Concatenate into a single buffer for hashing.
     */
    uint8_t buf[LTE_NAME_SIZE + LTE_HASH_SIZE + LTE_HASH_SIZE + 8];
    size_t  pos = 0;

    size_t nlen = strlen(artifact->name);
    memcpy(buf + pos, artifact->name, nlen);
    pos += nlen;

    memcpy(buf + pos, artifact->content_hash, LTE_HASH_SIZE);
    pos += LTE_HASH_SIZE;

    memcpy(buf + pos, artifact->prev_hash, LTE_HASH_SIZE);
    pos += LTE_HASH_SIZE;

    int64_t ts = artifact->timestamp;
    for (int i = 7; i >= 0; i--) {
        buf[pos + i] = (uint8_t)(ts & 0xff);
        ts >>= 8;
    }
    pos += 8;

    lte_sha256(buf, pos, artifact->link_hash);
    lte_hex(artifact->link_hash, artifact->link_hex);

    artifact->state = LTE_LINKED;
    return LTE_OK;
}

/* ─── Verify ──────────────────────────────────────────────────────────────── */

LTEResult lte_verify(const LTEArtifact *artifact,
                     const uint8_t *content,
                     size_t         content_len) {
    if (!artifact || !content) return LTE_ERR_NULL;

    /* recompute content_hash */
    uint8_t recomputed[LTE_HASH_SIZE];
    lte_sha256(content, content_len, recomputed);

    if (memcmp(recomputed, artifact->content_hash, LTE_HASH_SIZE) != 0)
        return LTE_ERR_HASH_MISMATCH;

    /* recompute link_hash */
    uint8_t buf[LTE_NAME_SIZE + LTE_HASH_SIZE + LTE_HASH_SIZE + 8];
    size_t  pos = 0;

    size_t nlen = strlen(artifact->name);
    memcpy(buf + pos, artifact->name, nlen);
    pos += nlen;

    memcpy(buf + pos, artifact->content_hash, LTE_HASH_SIZE);
    pos += LTE_HASH_SIZE;

    memcpy(buf + pos, artifact->prev_hash, LTE_HASH_SIZE);
    pos += LTE_HASH_SIZE;

    int64_t ts = artifact->timestamp;
    for (int i = 7; i >= 0; i--) {
        buf[pos + i] = (uint8_t)(ts & 0xff);
        ts >>= 8;
    }
    pos += 8;

    uint8_t link_check[LTE_HASH_SIZE];
    lte_sha256(buf, pos, link_check);

    if (memcmp(link_check, artifact->link_hash, LTE_HASH_SIZE) != 0)
        return LTE_ERR_HASH_MISMATCH;

    return LTE_OK;
}

/* ─── Execute ─────────────────────────────────────────────────────────────── */

LTEResult lte_execute(LTEArtifact *artifact) {
    if (!artifact) return LTE_ERR_NULL;

    if (artifact->state == LTE_REJECTED)
        return LTE_ERR_REJECTED;

    /* Constitutional rule: MUST be LINKED before EXECUTING */
    if (artifact->state != LTE_LINKED) {
        artifact->state = LTE_REJECTED;
        return LTE_ERR_UNLINKED;
    }

    artifact->state = LTE_EXECUTING;
    return LTE_OK;
}

/* ─── Chain ───────────────────────────────────────────────────────────────── */

LTEResult lte_chain_append(LTEChain *chain, const LTEArtifact *artifact) {
    if (!chain || !artifact) return LTE_ERR_NULL;
    if (chain->count >= LTE_MAX_CHAIN)  return LTE_ERR_OVERFLOW;
    if (artifact->state == LTE_UNLINKED || artifact->state == LTE_REJECTED)
        return LTE_ERR_UNLINKED;

    /* if not the first, verify prev_hash matches last artifact's link_hash */
    if (chain->count > 0) {
        const LTEArtifact *last = &chain->artifacts[chain->count - 1];
        if (memcmp(artifact->prev_hash, last->link_hash, LTE_HASH_SIZE) != 0)
            return LTE_ERR_CHAIN_BROKEN;
    }

    memcpy(&chain->artifacts[chain->count], artifact, sizeof(LTEArtifact));
    chain->count++;
    return LTE_OK;
}

LTEResult lte_chain_verify(const LTEChain *chain,
                            const uint8_t *contents[],
                            const size_t   content_lens[]) {
    if (!chain || !contents || !content_lens) return LTE_ERR_NULL;

    for (size_t i = 0; i < chain->count; i++) {
        const LTEArtifact *a = &chain->artifacts[i];

        LTEResult r = lte_verify(a, contents[i], content_lens[i]);
        if (r != LTE_OK) return r;

        /* check chain linkage */
        if (i > 0) {
            const LTEArtifact *prev = &chain->artifacts[i - 1];
            if (memcmp(a->prev_hash, prev->link_hash, LTE_HASH_SIZE) != 0)
                return LTE_ERR_CHAIN_BROKEN;
        }
    }
    return LTE_OK;
}
