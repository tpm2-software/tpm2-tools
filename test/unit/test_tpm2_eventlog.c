/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include <tss2/tss2_tpm2_types.h>

#include "tpm2_eventlog.h"

#define TCG_DIGEST2_SHA1_SIZE (sizeof(TCG_DIGEST2) + TPM2_SHA_DIGEST_SIZE)

static bool foreach_digest2_test_callback(TCG_DIGEST2 const *digest, size_t size, void *data){

    (void)digest;
    (void)size;
    (void)data;

    return mock_type(bool);
}
static void test_foreach_digest2_null(void **state){

    (void)state;

    assert_false(foreach_digest2(NULL, 0, sizeof(TCG_DIGEST2), NULL, NULL));
}
static void test_foreach_digest2_size(void **state) {

    (void)state;
    uint8_t buf [sizeof(TCG_DIGEST2) - 1] = { 0, };
    TCG_DIGEST2 *digest = (TCG_DIGEST2*)buf;

    assert_false(foreach_digest2(digest, 1, sizeof(TCG_DIGEST2) - 1, foreach_digest2_test_callback, NULL));
}
static void test_foreach_digest2(void **state) {

    (void)state;
    uint8_t buf [TCG_DIGEST2_SHA1_SIZE] = { 0, };
    TCG_DIGEST2* digest = (TCG_DIGEST2*)buf;

    will_return(foreach_digest2_test_callback, true);
    assert_true(foreach_digest2(digest, 1, TCG_DIGEST2_SHA1_SIZE, foreach_digest2_test_callback, NULL));
}
static void test_foreach_digest2_cbnull(void **state){

    (void)state;
    uint8_t buf [TCG_DIGEST2_SHA1_SIZE] = { 0, };
    TCG_DIGEST2* digest = (TCG_DIGEST2*)buf;

    assert_true(foreach_digest2(digest, 1, TCG_DIGEST2_SHA1_SIZE, NULL, NULL));
}
static void test_foreach_digest2_cbfail(void **state){

    (void)state;
    uint8_t buf [TCG_DIGEST2_SHA1_SIZE] = { 0, };
    TCG_DIGEST2* digest = (TCG_DIGEST2*)buf;

    will_return(foreach_digest2_test_callback, false);
    assert_false(foreach_digest2(digest, 1, TCG_DIGEST2_SHA1_SIZE, foreach_digest2_test_callback, NULL));
}
static void test_digest2_accumulator_callback(void **state) {

    (void)state;
    char buf[TCG_DIGEST2_SHA1_SIZE];
    TCG_DIGEST2 *digest = (TCG_DIGEST2*)buf;
    size_t size = TPM2_SHA1_DIGEST_SIZE, accumulated = 0;

    digest->AlgorithmId = TPM2_ALG_SHA1;
    assert_true(digest2_accumulator_callback (digest, size, &accumulated));
    assert_int_equal(accumulated, TCG_DIGEST2_SHA1_SIZE);
}
static void test_digest2_accumulator_callback_null(void **state) {

    (void)state;

    assert_false(digest2_accumulator_callback (NULL, 0, NULL));
}
static bool test_event2hdr_callback(TCG_EVENT_HEADER2 const *eventhdr, size_t size, void *data) {

    (void)eventhdr;
    (void)size;
    (void)data;

    return mock_type(bool);
}
static bool test_event2_callback(TCG_EVENT2 const *event, UINT32 type,
                                 bool validated, void *data) {

    (void)event;
    (void)type;
    (void)validated;
    (void)data;

    return mock_type(bool);
}

static void test_parse_event2_badhdr(void **state){

    (void)state;
    char buf[sizeof(TCG_EVENT_HEADER2) - 1] = { 0, };
    TCG_EVENT_HEADER2 *eventhdr = (TCG_EVENT_HEADER2*)buf;
    size_t size_event = 0, size_digest = 0;

    assert_false(parse_event2(eventhdr, sizeof(buf), &size_event, &size_digest));
}
static void test_parse_event2_baddigest(void **state){

    (void)state;
    char buf[sizeof(TCG_EVENT_HEADER2) + TCG_DIGEST2_SHA1_SIZE - 1] = { 0, };
    TCG_EVENT_HEADER2 *eventhdr = (TCG_EVENT_HEADER2*)buf;
    TCG_DIGEST2 *digest = eventhdr->Digests;
    size_t size_event = 0, size_digest = 0;

    eventhdr->DigestCount = 1;
    digest->AlgorithmId = TPM2_ALG_SHA1;

    assert_false(parse_event2(eventhdr, sizeof(buf), &size_event, &size_digest));
}
static void test_parse_event2_badeventsize(void **state){

    (void)state;
    char buf[sizeof(TCG_EVENT_HEADER2) + TCG_DIGEST2_SHA1_SIZE + sizeof(TCG_EVENT2) - 1] = { 0, };
    TCG_EVENT_HEADER2 *eventhdr = (TCG_EVENT_HEADER2*)buf;
    TCG_DIGEST2 *digest = eventhdr->Digests;
    size_t size_event = 0, size_digest = 0;

    eventhdr->DigestCount = 1;
    digest->AlgorithmId = TPM2_ALG_SHA1;

    assert_false(parse_event2(eventhdr, sizeof(buf), &size_event, &size_digest));
}
static void test_parse_event2_badeventbuf(void **state){

    (void)state;
    char buf[sizeof(TCG_EVENT_HEADER2) + TCG_DIGEST2_SHA1_SIZE + sizeof(TCG_EVENT2)] = { 0, };
    TCG_EVENT_HEADER2 *eventhdr = (TCG_EVENT_HEADER2*)buf;
    TCG_DIGEST2 *digest = eventhdr->Digests;
    TCG_EVENT2 *event = (TCG_EVENT2*)(buf + sizeof(*eventhdr) + TCG_DIGEST2_SHA1_SIZE);
    size_t size_event = 0, size_digest = 0;

    eventhdr->DigestCount = 1;
    digest->AlgorithmId = TPM2_ALG_SHA1;
    event->EventSize = 1;

    assert_false(parse_event2(eventhdr, sizeof(buf), &size_event, &size_digest));
}
static void test_foreach_event2_null(void **state){

    (void)state;

    assert_false(foreach_event2(NULL, 0, NULL, NULL, NULL, NULL));
}
static void test_foreach_event2(void **state){

    (void)state;
    char buf[sizeof(TCG_EVENT_HEADER2) + TCG_DIGEST2_SHA1_SIZE + sizeof(TCG_EVENT2) + 6] = { 0, };
    TCG_EVENT_HEADER2 *eventhdr = (TCG_EVENT_HEADER2*)buf;
    TCG_DIGEST2 *digest = eventhdr->Digests;
    TCG_EVENT2 *event = (TCG_EVENT2*)((uintptr_t)digest + TCG_DIGEST2_SHA1_SIZE);

    eventhdr->DigestCount = 1;
    digest->AlgorithmId = TPM2_ALG_SHA1;
    event->EventSize = 6;

    will_return(test_event2hdr_callback, true);
    will_return(foreach_digest2_test_callback, true);
    will_return(test_event2_callback, true);
    assert_true(foreach_event2(eventhdr, sizeof(buf), test_event2hdr_callback,
                               foreach_digest2_test_callback,
                               test_event2_callback, NULL));
}
static void test_foreach_event2_event2hdr_fail(void **state){

    (void)state;
    char buf[sizeof(TCG_EVENT_HEADER2) + TCG_DIGEST2_SHA1_SIZE + sizeof(TCG_EVENT2) + 1] = { 0, };
    TCG_EVENT_HEADER2 *eventhdr = (TCG_EVENT_HEADER2*)buf;
    TCG_DIGEST2 *digest = eventhdr->Digests;
    TCG_EVENT2 *event = (TCG_EVENT2*)(buf + sizeof(*eventhdr) + TCG_DIGEST2_SHA1_SIZE);

    eventhdr->DigestCount = 1;
    digest->AlgorithmId = TPM2_ALG_SHA1;
    event->EventSize = 1;

    will_return(test_event2hdr_callback, false);
    assert_false(foreach_event2(eventhdr, sizeof(buf), test_event2hdr_callback,
                                NULL, NULL, NULL));
}
static void test_foreach_event2_digest2_fail(void **state){

    (void)state;
    char buf[sizeof(TCG_EVENT_HEADER2) + TCG_DIGEST2_SHA1_SIZE + sizeof(TCG_EVENT2) + 1] = { 0, };
    TCG_EVENT_HEADER2 *eventhdr = (TCG_EVENT_HEADER2*)buf;
    TCG_DIGEST2 *digest = eventhdr->Digests;
    TCG_EVENT2 *event = (TCG_EVENT2*)(buf + sizeof(*eventhdr) + TCG_DIGEST2_SHA1_SIZE);

    eventhdr->DigestCount = 1;
    digest->AlgorithmId = TPM2_ALG_SHA1;
    event->EventSize = 1;

    will_return(test_event2hdr_callback, true);
    will_return(foreach_digest2_test_callback, false);
    assert_false(foreach_event2(eventhdr, sizeof(buf),
                                test_event2hdr_callback,
                                foreach_digest2_test_callback, NULL, NULL));
}
static void test_foreach_event2_event2body_fail(void **state){

    (void)state;
    char buf[sizeof(TCG_EVENT_HEADER2) + TCG_DIGEST2_SHA1_SIZE + sizeof(TCG_EVENT2) + 1] = { 0, };
    TCG_EVENT_HEADER2 *eventhdr = (TCG_EVENT_HEADER2*)buf;
    TCG_DIGEST2 *digest = eventhdr->Digests;
    TCG_EVENT2 *event = (TCG_EVENT2*)(buf + sizeof(*eventhdr) + TCG_DIGEST2_SHA1_SIZE);

    eventhdr->DigestCount = 1;
    digest->AlgorithmId = TPM2_ALG_SHA1;
    event->EventSize = 1;

    will_return(test_event2hdr_callback, true);
    will_return(foreach_digest2_test_callback, true);
    will_return(test_event2_callback, false);
    assert_false(foreach_event2(eventhdr, sizeof(buf),
                                test_event2hdr_callback,
                                foreach_digest2_test_callback,
                                test_event2_callback, NULL));
}
int main(void) {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_foreach_digest2_null),
        cmocka_unit_test(test_foreach_digest2_size),
        cmocka_unit_test(test_foreach_digest2),
        cmocka_unit_test(test_foreach_digest2_cbfail),
        cmocka_unit_test(test_foreach_digest2_cbnull),
        cmocka_unit_test(test_digest2_accumulator_callback),
        cmocka_unit_test(test_digest2_accumulator_callback_null),
        cmocka_unit_test(test_parse_event2_badhdr),
        cmocka_unit_test(test_parse_event2_baddigest),
        cmocka_unit_test(test_parse_event2_badeventsize),
        cmocka_unit_test(test_parse_event2_badeventbuf),
        cmocka_unit_test(test_foreach_event2_null),
        cmocka_unit_test(test_foreach_event2),
        cmocka_unit_test(test_foreach_event2_event2hdr_fail),
        cmocka_unit_test(test_foreach_event2_event2body_fail),
        cmocka_unit_test(test_foreach_event2_digest2_fail),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
