/*
 * nsigii_lte_test.c — LTE verification test harness
 * OBINexus SDK | MMUKO OS Design and Technology LLC
 * Author: Nnamdi Michael Okpala
 */

#include "nsigii_lte.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int passed = 0;
static int failed = 0;

#define TEST(label, expr) do { \
    if (expr) { printf("  PASS  %s\n", label); passed++; } \
    else       { printf("  FAIL  %s\n", label); failed++; } \
} while(0)

/* ─── SHA-256 known-answer test ───────────────────────────────────────────── */
static void test_sha256_kat(void) {
    printf("\n[SHA-256 known-answer]\n");
    /* SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
    uint8_t out[LTE_HASH_SIZE];
    lte_sha256((const uint8_t *)"", 0, out);
    char hex[LTE_HASH_HEX_SIZE];
    lte_hex(out, hex);
    TEST("SHA-256('') known answer",
         strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb924"
                     "27ae41e4649b934ca495991b7852b855") == 0);

    /* SHA-256("abc") = ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469849678820950f06ce28 */
    lte_sha256((const uint8_t *)"abc", 3, out);
    lte_hex(out, hex);
    TEST("SHA-256('abc') known answer",
         strcmp(hex, "ba7816bf8f01cfea414140de5dae2223"
                     "b00361a396177a9cb410ff61f20015ad") == 0);
}

/* ─── Link → verify → execute (happy path) ───────────────────────────────── */
static void test_lte_happy_path(void) {
    printf("\n[LTE happy path: link → verify → execute]\n");

    const uint8_t *content = (const uint8_t *)"NSIGII food delivery artifact v1";
    size_t len = strlen((const char *)content);

    LTEArtifact artifact;
    memset(&artifact, 0, sizeof(artifact));

    LTEResult r = lte_link(&artifact, "food_delivery_v1", content, len, NULL);
    TEST("lte_link returns OK",               r == LTE_OK);
    TEST("state is LINKED after link",        artifact.state == LTE_LINKED);
    TEST("content_hex is non-empty",          artifact.content_hex[0] != '\0');
    TEST("link_hex is non-empty",             artifact.link_hex[0] != '\0');

    r = lte_verify(&artifact, content, len);
    TEST("lte_verify returns OK",             r == LTE_OK);

    r = lte_execute(&artifact);
    TEST("lte_execute returns OK",            r == LTE_OK);
    TEST("state is EXECUTING after execute",  artifact.state == LTE_EXECUTING);
}

/* ─── Execute without link → REJECTED ────────────────────────────────────── */
static void test_lte_execute_without_link(void) {
    printf("\n[LTE constitutional rule: no execute without link]\n");

    LTEArtifact artifact;
    memset(&artifact, 0, sizeof(artifact));
    artifact.state = LTE_UNLINKED;

    LTEResult r = lte_execute(&artifact);
    TEST("execute on UNLINKED returns ERR_UNLINKED", r == LTE_ERR_UNLINKED);
    TEST("state is REJECTED after illegal execute",  artifact.state == LTE_REJECTED);

    /* once rejected, further execute attempts fail */
    r = lte_execute(&artifact);
    TEST("execute on REJECTED returns ERR_REJECTED", r == LTE_ERR_REJECTED);
}

/* ─── Tamper detection ────────────────────────────────────────────────────── */
static void test_lte_tamper(void) {
    printf("\n[LTE tamper detection]\n");

    const uint8_t *original  = (const uint8_t *)"food water shelter";
    const uint8_t *tampered  = (const uint8_t *)"food water nothing";
    size_t len = strlen((const char *)original);

    LTEArtifact artifact;
    memset(&artifact, 0, sizeof(artifact));
    lte_link(&artifact, "delivery_packet", original, len, NULL);

    /* verify with tampered content — must fail */
    LTEResult r = lte_verify(&artifact, tampered, len);
    TEST("tampered content detected",  r == LTE_ERR_HASH_MISMATCH);
}

/* ─── Chain: two linked artifacts ────────────────────────────────────────── */
static void test_lte_chain(void) {
    printf("\n[LTE chain: two artifacts, prev_hash linkage]\n");

    const uint8_t *c0 = (const uint8_t *)"packet zero: IDLE state";
    const uint8_t *c1 = (const uint8_t *)"packet one:  HUNGRY state";
    size_t l0 = strlen((const char *)c0);
    size_t l1 = strlen((const char *)c1);

    LTEArtifact a0, a1;
    memset(&a0, 0, sizeof(a0));
    memset(&a1, 0, sizeof(a1));

    lte_link(&a0, "packet_0", c0, l0, NULL);
    lte_link(&a1, "packet_1", c1, l1, a0.link_hash); /* prev = a0 */

    LTEChain chain;
    memset(&chain, 0, sizeof(chain));

    LTEResult r0 = lte_chain_append(&chain, &a0);
    LTEResult r1 = lte_chain_append(&chain, &a1);
    TEST("chain append a0 OK",              r0 == LTE_OK);
    TEST("chain append a1 OK",              r1 == LTE_OK);
    TEST("chain count is 2",                chain.count == 2);

    const uint8_t *contents[]   = { c0, c1 };
    size_t         lens[]       = { l0, l1 };
    LTEResult rv = lte_chain_verify(&chain, contents, lens);
    TEST("chain verify passes",             rv == LTE_OK);
}

/* ─── Chain: broken linkage detected ─────────────────────────────────────── */
static void test_lte_chain_broken(void) {
    printf("\n[LTE chain: broken prev_hash detected]\n");

    const uint8_t *c0 = (const uint8_t *)"genesis packet";
    const uint8_t *c1 = (const uint8_t *)"second packet with wrong prev";
    size_t l0 = strlen((const char *)c0);
    size_t l1 = strlen((const char *)c1);

    LTEArtifact a0, a1;
    memset(&a0, 0, sizeof(a0));
    memset(&a1, 0, sizeof(a1));

    lte_link(&a0, "genesis",  c0, l0, NULL);
    lte_link(&a1, "orphan",   c1, l1, NULL); /* wrong: prev should be a0.link_hash */

    LTEChain chain;
    memset(&chain, 0, sizeof(chain));
    lte_chain_append(&chain, &a0);

    LTEResult r = lte_chain_append(&chain, &a1);
    TEST("broken chain detected on append", r == LTE_ERR_CHAIN_BROKEN);
    TEST("chain count stays at 1",          chain.count == 1);
}

/* ─── Main ────────────────────────────────────────────────────────────────── */
int main(void) {
    printf("NSIGII LTE — Linkable Then Executable\n");
    printf("OBINexus SDK | MMUKO OS\n");
    printf("======================================\n");

    test_sha256_kat();
    test_lte_happy_path();
    test_lte_execute_without_link();
    test_lte_tamper();
    test_lte_chain();
    test_lte_chain_broken();

    printf("\n======================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
