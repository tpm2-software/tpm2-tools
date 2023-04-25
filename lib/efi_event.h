/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef TCG_EFI_EVENT_H
#define TCG_EFI_EVENT_H 1

#include <uchar.h>
#include <tss2/tss2_tpm2_types.h>

/*
 * Log event types. These are spread out over 2 specs:
 * "TCG EFI Protocol Specification For TPM Family 1.1 or 1.2" and
 * "TCG PC Client Specific Implementation Specification for Conventional BIOS"
 */
#define EV_PREBOOT_CERT            0x0
#define EV_POST_CODE               0x1
#define EV_UNUSED                  0x2
#define EV_NO_ACTION               0x3
#define EV_SEPARATOR               0x4
#define EV_ACTION                  0x5
#define EV_EVENT_TAG               0x6
#define EV_S_CRTM_CONTENTS         0x7
#define EV_S_CRTM_VERSION          0x8
#define EV_CPU_MICROCODE           0x9
#define EV_PLATFORM_CONFIG_FLAGS   0xa
#define EV_TABLE_OF_DEVICES        0xb
#define EV_COMPACT_HASH            0xc
#define EV_IPL                     0xd
#define EV_IPL_PARTITION_DATA      0xe
#define EV_NONHOST_CODE            0xf
#define EV_NONHOST_CONFIG          0x10
#define EV_NONHOST_INFO            0x11
#define EV_OMIT_BOOT_DEVICE_EVENTS 0x12

/* TCG EFI Platform Specification For TPM Family 1.1 or 1.2 */
#define EV_EFI_EVENT_BASE                0x80000000
#define EV_EFI_VARIABLE_DRIVER_CONFIG    EV_EFI_EVENT_BASE + 0x1
#define EV_EFI_VARIABLE_BOOT             EV_EFI_EVENT_BASE + 0x2
#define EV_EFI_BOOT_SERVICES_APPLICATION EV_EFI_EVENT_BASE + 0x3
#define EV_EFI_BOOT_SERVICES_DRIVER      EV_EFI_EVENT_BASE + 0x4
#define EV_EFI_RUNTIME_SERVICES_DRIVER   EV_EFI_EVENT_BASE + 0x5
#define EV_EFI_GPT_EVENT                 EV_EFI_EVENT_BASE + 0x6
#define EV_EFI_ACTION                    EV_EFI_EVENT_BASE + 0x7
#define EV_EFI_PLATFORM_FIRMWARE_BLOB    EV_EFI_EVENT_BASE + 0x8
#define EV_EFI_HANDOFF_TABLES            EV_EFI_EVENT_BASE + 0x9
#define EV_EFI_PLATFORM_FIRMWARE_BLOB2   EV_EFI_EVENT_BASE + 0xa
#define EV_EFI_HANDOFF_TABLES2           EV_EFI_EVENT_BASE + 0xb
#define EV_EFI_VARIABLE_BOOT2            EV_EFI_EVENT_BASE + 0xc

#define EV_EFI_HCRTM_EVENT               EV_EFI_EVENT_BASE + 0x10
#define EV_EFI_VARIABLE_AUTHORITY        EV_EFI_EVENT_BASE + 0xe0

#ifndef PACKED
#define PACKED __attribute__((__packed__))
#endif

/* GUIDs used by UEFI/GPT are stored in a mixed-endian layout, where the first
 * three fields are serialized as little-endian and the final two fields are
 * serialized as big-endian. This differs from uuid_t which is entirely a
 * big-endian layout (just an array of 16 bytes).
 */
typedef struct {
  UINT32 Data1;
  UINT16 Data2;
  UINT16 Data3;
  UINT8 Data4[8];
} PACKED EFI_GUID;

typedef struct {
  UINT16 AlgorithmId;
  UINT8 Digest[];
} PACKED TCG_DIGEST2;

typedef struct {
  UINT32 EventSize;
  UINT8 Event [];
} PACKED TCG_EVENT2;

typedef struct {
  UINT32 PCRIndex;
  UINT32 EventType;
  UINT32 DigestCount;
  TCG_DIGEST2 Digests [];
 /* TCG_EVENT2 comes next */
} PACKED TCG_EVENT_HEADER2;

/* Helper structure for dealing with unaligned char16_t */
typedef struct {
    char16_t c;
} PACKED UTF16_CHAR;

typedef struct {
  EFI_GUID VariableName;
  UINT64 UnicodeNameLength;
  UINT64 VariableDataLength;
  UTF16_CHAR UnicodeName[];
  /* INT8 VariableData[] comes next */
} PACKED UEFI_VARIABLE_DATA;

typedef UINT64 UEFI_PHYSICAL_ADDRESS;
typedef struct {
    UEFI_PHYSICAL_ADDRESS BlobBase;
    UINT64 BlobLength;
} PACKED UEFI_PLATFORM_FIRMWARE_BLOB;


typedef struct {
  UINT8 BlobDescriptionSize;
  BYTE  BlobDescription[];
  /* UEFI_PLATFORM_FIRMWARE_BLOB comes next */
} PACKED UEFI_PLATFORM_FIRMWARE_BLOB2;

typedef struct {
    UINT32 pcrIndex;
    UINT32 eventType;
    BYTE digest[20];
    UINT32 eventDataSize;
    BYTE event[];
} PACKED TCG_EVENT;

typedef struct {
    UINT16 algorithmId;
    UINT16 digestSize;
} PACKED TCG_SPECID_ALG;

typedef struct {
    UINT8 vendorInfoSize;
    BYTE vendorInfo[];
} PACKED TCG_VENDOR_INFO;

typedef struct {
    BYTE Signature[16];
    UINT32 platformClass;
    UINT8 specVersionMinor;
    UINT8 specVersionMajor;
    UINT8 specErrata;
    UINT8 uintnSize;
    UINT32 numberOfAlgorithms;
    TCG_SPECID_ALG digestSizes[];
    /* then TCG_VendorStuff */
} PACKED TCG_SPECID_EVENT;

typedef struct {
    UEFI_PHYSICAL_ADDRESS ImageLocationInMemory;
    UINT64 ImageLengthInMemory;
    UINT64 ImageLinkTimeAddress;
    UINT64 LengthOfDevicePath;
    BYTE DevicePath[];
} PACKED UEFI_IMAGE_LOAD_EVENT;

/* 
   These structs represent a GUID Partition Table. UEFI_GPT_DATA is defined in
   the TGC PC Client Platform Firmware Profile Specification Version 1.05,
   Revision 23, Table 10. UEFI_PARTITION_TABLE_HEADER and UEFI_PARTITION_ENTRY
   are defined in the UEFI Specification Version 2.9, Section 5.3.
 */
typedef struct {
    UINT64 Signature;
    UINT32 Revision;
    UINT32 HeaderSize;
    UINT32 HeaderCRC32;
    UINT32 Reserved;
    UINT64 MyLBA;
    UINT64 AlternateLBA;
    UINT64 FirstUsableLBA;
    UINT64 LastUsableLBA;
    EFI_GUID DiskGUID;
    UINT64 PartitionEntryLBA;
    UINT32 NumberOfPartitionEntries;
    UINT32 SizeOfPartitionEntry;
    UINT32 PartitionEntryArrayCRC32;
} PACKED UEFI_PARTITION_TABLE_HEADER;

typedef struct {
    EFI_GUID PartitionTypeGUID;
    EFI_GUID UniquePartitionGUID;
    UINT64 StartingLBA;
    UINT64 EndingLBA;
    UINT64 Attributes;
    /* To make the entire struct 128 bytes, PartitionName is 36 characters. */
    UTF16_CHAR PartitionName[36];
} PACKED UEFI_PARTITION_ENTRY;

typedef struct {
    UEFI_PARTITION_TABLE_HEADER UEFIPartitionHeader;
    UINT64 NumberOfPartitions;
    UEFI_PARTITION_ENTRY Partitions[];
} PACKED UEFI_GPT_DATA;

/*
 * An UEFI signature database is represented as a concatenated list of
 * EFI_SIGNATURE_LIST, which contains one or more EFI_SIGNATURE_DATA. These
 * structs are described in more details in UEFI Spec Section 32.4.1
 */
typedef struct {
    EFI_GUID SignatureType;
    UINT32 SignatureListSize;
    UINT32 SignatureHeaderSize;
    UINT32 SignatureSize;
    // BYTE SignatureHeader[SignatureHeaderSize];
    // BYTE Signatures[][SignatureSize];
} PACKED EFI_SIGNATURE_LIST;

typedef struct {
    EFI_GUID SignatureOwner;
    BYTE SignatureData[];
} PACKED EFI_SIGNATURE_DATA;

/*
 * EFI_LOAD_OPTION describes a load option variable. This struct is described
 * in more details in UEFI Spec Section 3.1.3
 */
typedef struct {
    UINT32 Attributes;
    UINT16 FilePathListLength;
    UINT16 Description[];
    // EFI_DEVICE_PATH_PROTOCOL FilePathList[];
    // UINT8 OptionalData[];
} PACKED EFI_LOAD_OPTION;

/*
 * EV_NO_ACTION_STRUCT is the structure of an EV_NO_ACTION event.
 * Described in TCG PCClient PFP section 9.4.5.
 * The Signature identifies which arm of the union applies.
 */
typedef struct {
    BYTE Signature[16];
    union {
        BYTE StartupLocality;
    } Cases;
} PACKED EV_NO_ACTION_STRUCT;

static const BYTE STARTUP_LOCALITY_SIGNATURE[16] = {0x53, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x4C,
    0x6F, 0x63, 0x61, 0x6C, 0x69, 0x74, 0x79, 0};

#endif
