/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include <tss2/tss2_tpm2_types.h>

#include "tpm2_eventlog_yaml.h"

#define TCG_DIGEST2_SHA1_SIZE (sizeof(TCG_DIGEST2) + TPM2_SHA_DIGEST_SIZE)

#define def_eventtype_to_string(ev) \
static void eventtype_to_string_##ev(void **state){ \
    (void)state; \
    assert_string_equal(eventtype_to_string(ev), #ev); \
}

def_eventtype_to_string(EV_PREBOOT_CERT)
def_eventtype_to_string(EV_POST_CODE)
def_eventtype_to_string(EV_UNUSED)
def_eventtype_to_string(EV_NO_ACTION)
def_eventtype_to_string(EV_SEPARATOR)
def_eventtype_to_string(EV_ACTION)
def_eventtype_to_string(EV_EVENT_TAG)
def_eventtype_to_string(EV_S_CRTM_CONTENTS)
def_eventtype_to_string(EV_S_CRTM_VERSION)
def_eventtype_to_string(EV_CPU_MICROCODE)
def_eventtype_to_string(EV_PLATFORM_CONFIG_FLAGS)
def_eventtype_to_string(EV_TABLE_OF_DEVICES)
def_eventtype_to_string(EV_COMPACT_HASH)
def_eventtype_to_string(EV_IPL)
def_eventtype_to_string(EV_IPL_PARTITION_DATA)
def_eventtype_to_string(EV_NONHOST_CODE)
def_eventtype_to_string(EV_NONHOST_CONFIG)
def_eventtype_to_string(EV_NONHOST_INFO)
def_eventtype_to_string(EV_OMIT_BOOT_DEVICE_EVENTS)
def_eventtype_to_string(EV_EFI_VARIABLE_DRIVER_CONFIG)
def_eventtype_to_string(EV_EFI_VARIABLE_BOOT)
def_eventtype_to_string(EV_EFI_BOOT_SERVICES_APPLICATION)
def_eventtype_to_string(EV_EFI_BOOT_SERVICES_DRIVER)
def_eventtype_to_string(EV_EFI_RUNTIME_SERVICES_DRIVER)
def_eventtype_to_string(EV_EFI_GPT_EVENT)
def_eventtype_to_string(EV_EFI_ACTION)
def_eventtype_to_string(EV_EFI_PLATFORM_FIRMWARE_BLOB)
def_eventtype_to_string(EV_EFI_HANDOFF_TABLES)
def_eventtype_to_string(EV_EFI_PLATFORM_FIRMWARE_BLOB2)
def_eventtype_to_string(EV_EFI_HANDOFF_TABLES2)
def_eventtype_to_string(EV_EFI_VARIABLE_BOOT2)
def_eventtype_to_string(EV_EFI_VARIABLE_AUTHORITY)

static void eventtype_to_string_default(void **state) {
    (void)state;
    assert_string_equal(eventtype_to_string(666), "Unknown event type");
}

static void test_yaml_digest2_callback(void **state) {

    (void)state;
    uint8_t buf [TCG_DIGEST2_SHA1_SIZE];
    TCG_DIGEST2 *digest = (TCG_DIGEST2*)buf;
    size_t count = 0;

    digest->AlgorithmId = TPM2_ALG_SHA1;
    assert_true(yaml_digest2_callback(digest, TPM2_SHA1_DIGEST_SIZE, &count));
}
static void test_yaml_event2data_version1(void **state) {

    (void)state;
    uint8_t buf [sizeof(TCG_EVENT2) + 6];
    TCG_EVENT2 *event = (TCG_EVENT2*)buf;

    event->EventSize = 6;
    assert_true(yaml_event2data(event, EV_PREBOOT_CERT, 1));
}
static void test_yaml_event2data_version2(void **state) {

    (void)state;
    uint8_t buf [sizeof(TCG_EVENT2) + 6];
    TCG_EVENT2 *event = (TCG_EVENT2*)buf;

    event->EventSize = 6;
    assert_true(yaml_event2data(event, EV_PREBOOT_CERT, 2));
}
static void test_yaml_event2hdr_callback(void **state){

    (void)state;
    uint8_t buf [sizeof(TCG_EVENT_HEADER2) + TCG_DIGEST2_SHA1_SIZE + sizeof(TCG_EVENT2) + 2] = { 0, };
    TCG_EVENT_HEADER2 *eventhdr = (TCG_EVENT_HEADER2*)buf;
    TCG_DIGEST2 *digest = (TCG_DIGEST2*)(eventhdr->Digests);
    TCG_EVENT2 *event = (TCG_EVENT2*)(buf + sizeof(*eventhdr) + TCG_DIGEST2_SHA1_SIZE);
    size_t count = 0;

    eventhdr->DigestCount = 1;
    digest->AlgorithmId = TPM2_ALG_SHA1;
    digest->Digest[0] = 0xef;
    event->EventSize = 2;

    assert_true(yaml_event2hdr_callback(eventhdr, sizeof(buf), &count));
}
static void test_yaml_event2hdr_callback_nulldata(void **state){

    (void)state;

    assert_false(yaml_event2hdr_callback(NULL, 0, NULL));
}
static void test_yaml_eventlog(void **state){

    (void)state;

    assert_false(yaml_eventlog(NULL, 0, 1));
}
int main(void) {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(eventtype_to_string_EV_PREBOOT_CERT),
        cmocka_unit_test(eventtype_to_string_EV_POST_CODE),
        cmocka_unit_test(eventtype_to_string_EV_UNUSED),
        cmocka_unit_test(eventtype_to_string_EV_NO_ACTION),
        cmocka_unit_test(eventtype_to_string_EV_SEPARATOR),
        cmocka_unit_test(eventtype_to_string_EV_ACTION),
        cmocka_unit_test(eventtype_to_string_EV_EVENT_TAG),
        cmocka_unit_test(eventtype_to_string_EV_S_CRTM_CONTENTS),
        cmocka_unit_test(eventtype_to_string_EV_S_CRTM_VERSION),
        cmocka_unit_test(eventtype_to_string_EV_CPU_MICROCODE),
        cmocka_unit_test(eventtype_to_string_EV_PLATFORM_CONFIG_FLAGS),
        cmocka_unit_test(eventtype_to_string_EV_TABLE_OF_DEVICES),
        cmocka_unit_test(eventtype_to_string_EV_COMPACT_HASH),
        cmocka_unit_test(eventtype_to_string_EV_IPL),
        cmocka_unit_test(eventtype_to_string_EV_IPL_PARTITION_DATA),
        cmocka_unit_test(eventtype_to_string_EV_NONHOST_CODE),
        cmocka_unit_test(eventtype_to_string_EV_NONHOST_CONFIG),
        cmocka_unit_test(eventtype_to_string_EV_NONHOST_INFO),
        cmocka_unit_test(eventtype_to_string_EV_OMIT_BOOT_DEVICE_EVENTS),
        cmocka_unit_test(eventtype_to_string_EV_EFI_VARIABLE_DRIVER_CONFIG),
        cmocka_unit_test(eventtype_to_string_EV_EFI_VARIABLE_BOOT),
        cmocka_unit_test(eventtype_to_string_EV_EFI_BOOT_SERVICES_APPLICATION),
        cmocka_unit_test(eventtype_to_string_EV_EFI_BOOT_SERVICES_DRIVER),
        cmocka_unit_test(eventtype_to_string_EV_EFI_RUNTIME_SERVICES_DRIVER),
        cmocka_unit_test(eventtype_to_string_EV_EFI_GPT_EVENT),
        cmocka_unit_test(eventtype_to_string_EV_EFI_ACTION),
        cmocka_unit_test(eventtype_to_string_EV_EFI_PLATFORM_FIRMWARE_BLOB),
        cmocka_unit_test(eventtype_to_string_EV_EFI_HANDOFF_TABLES),
        cmocka_unit_test(eventtype_to_string_EV_EFI_PLATFORM_FIRMWARE_BLOB2),
        cmocka_unit_test(eventtype_to_string_EV_EFI_HANDOFF_TABLES2),
        cmocka_unit_test(eventtype_to_string_EV_EFI_VARIABLE_BOOT2),
        cmocka_unit_test(eventtype_to_string_EV_EFI_VARIABLE_AUTHORITY),
        cmocka_unit_test(eventtype_to_string_default),
        cmocka_unit_test(test_yaml_event2hdr_callback),
        cmocka_unit_test(test_yaml_event2hdr_callback_nulldata),
        cmocka_unit_test(test_yaml_digest2_callback),
        cmocka_unit_test(test_yaml_event2data_version1),
        cmocka_unit_test(test_yaml_event2data_version2),
        cmocka_unit_test(test_yaml_eventlog),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
