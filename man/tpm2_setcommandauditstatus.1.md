% tpm2_setcommandauditstatus(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_setcommandauditstatus**(1) - Add or remove TPM2 commands to the audited
commands list.

# SYNOPSIS

**tpm2_setcommandauditstatus** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_setcommandauditstatus**(1) - Add or remove TPM2 commands to the audited
commands list.

As an argument it takes the command as an integer or friendly string value.
Friendly string to COMMAND CODE mapping can be found in section
*COMMAND CODE MAPPINGS*.

# OPTIONS

  * **-C**, **\--hierarchy**=_OBJECT_:

    Specify either owner or platform hierarchy. Defaults to **TPM_RH_OWNER**,
    when no value has been specified.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**

  * **-P**, **\--hierarchy-auth**=_AUTH_:
    Specifies the authorization value for the hierarchy. Authorization values
    should follow the "authorization formatting standards", see section
    "Authorization Formatting".

  * **-c**, **\--clear-list**:
    Specifies that the TPM command specified has to be taken off the audit list.
    When not specified, the default behaviour is to add the TPM command to the
    audit list.

  * **-g**, **\--hash-algorithm**=_ALGORITHM_:

    Sets up the hashing algorithm for the audit digest. When not specified,
    the default audit digest algorithm is set to SHA256.

  * **ARGUMENT** the command line argument specifies TPM2 command code.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

[hash algorithm options](common/hash.md) collection of options to specify hash
algorithm.


# COMMAND CODE MAPPINGS

The friendly strings below can be used en lieu of the raw integer values.

  -TPM2\_CC\_AC\_GetCapability: 0x194
  -TPM2\_CC\_AC\_Send: 0x195
  -TPM2\_CC\_ActivateCredential: 0x147
  -TPM2\_CC\_Certify: 0x148
  -TPM2\_CC\_CertifyCreation: 0x14a
  -TPM2\_CC\_ChangeEPS: 0x124
  -TPM2\_CC\_ChangePPS: 0x125
  -TPM2\_CC\_Clear: 0x126
  -TPM2\_CC\_ClearControl: 0x127
  -TPM2\_CC\_ClockRateAdjust: 0x130
  -TPM2\_CC\_ClockSet: 0x128
  -TPM2\_CC\_Commit: 0x18b
  -TPM2\_CC\_ContextLoad: 0x161
  -TPM2\_CC\_ContextSave: 0x162
  -TPM2\_CC\_Create: 0x153
  -TPM2\_CC\_CreateLoaded: 0x191
  -TPM2\_CC\_CreatePrimary: 0x131
  -TPM2\_CC\_DictionaryAttackLockReset: 0x139
  -TPM2\_CC\_DictionaryAttackParameters: 0x13a
  -TPM2\_CC\_Duplicate: 0x14b
  -TPM2\_CC\_ECC\_Parameters: 0x178
  -TPM2\_CC\_ECDH\_KeyGen: 0x163
  -TPM2\_CC\_ECDH\_ZGen: 0x154
  -TPM2\_CC\_EC\_Ephemeral: 0x18e
  -TPM2\_CC\_EncryptDecrypt: 0x164
  -TPM2\_CC\_EncryptDecrypt2: 0x193
  -TPM2\_CC\_EventSequenceComplete: 0x185
  -TPM2\_CC\_EvictControl: 0x120
  -TPM2\_CC\_FieldUpgradeData: 0x141
  -TPM2\_CC\_FieldUpgradeStart: 0x12f
  -TPM2\_CC\_FirmwareRead: 0x179
  -TPM2\_CC\_FlushContext: 0x165
  -TPM2\_CC\_GetCapability: 0x17a
  -TPM2\_CC\_GetCommandAuditDigest: 0x133
  -TPM2\_CC\_GetRandom: 0x17b
  -TPM2\_CC\_GetSessionAuditDigest: 0x14d
  -TPM2\_CC\_GetTestResult: 0x17c
  -TPM2\_CC\_GetTime: 0x14c
  -TPM2\_CC\_Hash: 0x17d
  -TPM2\_CC\_HashSequenceStart: 0x186
  -TPM2\_CC\_HierarchyChangeAuth: 0x129
  -TPM2\_CC\_HierarchyControl: 0x121
  -TPM2\_CC\_HMAC: 0x155
  -TPM2\_CC\_HMAC\_Start: 0x15b
  -TPM2\_CC\_Import: 0x156
  -TPM2\_CC\_IncrementalSelfTest: 0x142
  -TPM2\_CC\_Load: 0x157
  -TPM2\_CC\_LoadExternal: 0x167
  -TPM2\_CC\_MakeCredential: 0x168
  -TPM2\_CC\_NV\_Certify: 0x184
  -TPM2\_CC\_NV\_ChangeAuth: 0x13b
  -TPM2\_CC\_NV\_DefineSpace: 0x12a
  -TPM2\_CC\_NV\_Extend: 0x136
  -TPM2\_CC\_NV\_GlobalWriteLock: 0x132
  -TPM2\_CC\_NV\_Increment: 0x134
  -TPM2\_CC\_NV\_Read: 0x14e
  -TPM2\_CC\_NV\_ReadLock: 0x14f
  -TPM2\_CC\_NV\_ReadPublic: 0x169
  -TPM2\_CC\_NV\_SetBits: 0x135
  -TPM2\_CC\_NV\_UndefineSpace: 0x122
  -TPM2\_CC\_NV\_UndefineSpaceSpecial: 0x11f
  -TPM2\_CC\_NV\_Write: 0x137
  -TPM2\_CC\_NV\_WriteLock: 0x138
  -TPM2\_CC\_ObjectChangeAuth: 0x150
  -TPM2\_CC\_PCR\_Allocate: 0x12b
  -TPM2\_CC\_PCR\_Event: 0x13c
  -TPM2\_CC\_PCR\_Extend: 0x182
  -TPM2\_CC\_PCR\_Read: 0x17e
  -TPM2\_CC\_PCR\_Reset: 0x13d
  -TPM2\_CC\_PCR\_SetAuthPolicy: 0x12c
  -TPM2\_CC\_PCR\_SetAuthValue: 0x183
  -TPM2\_CC\_Policy\_AC\_SendSelect: 0x196
  -TPM2\_CC\_PolicyAuthorize: 0x16a
  -TPM2\_CC\_PolicyAuthorizeNV: 0x192
  -TPM2\_CC\_PolicyAuthValue: 0x16b
  -TPM2\_CC\_PolicyCommandCode: 0x16c
  -TPM2\_CC\_PolicyCounterTimer: 0x16d
  -TPM2\_CC\_PolicyCpHash: 0x16e
  -TPM2\_CC\_PolicyDuplicationSelect: 0x188
  -TPM2\_CC\_PolicyGetDigest: 0x189
  -TPM2\_CC\_PolicyLocality: 0x16f
  -TPM2\_CC\_PolicyNameHash: 0x170
  -TPM2\_CC\_PolicyNV: 0x149
  -TPM2\_CC\_PolicyNvWritten: 0x18f
  -TPM2\_CC\_PolicyOR: 0x171
  -TPM2\_CC\_PolicyPassword: 0x18c
  -TPM2\_CC\_PolicyPCR: 0x17f
  -TPM2\_CC\_PolicyPhysicalPresence: 0x187
  -TPM2\_CC\_PolicyRestart: 0x180
  -TPM2\_CC\_PolicySecret: 0x151
  -TPM2\_CC\_PolicySigned: 0x160
  -TPM2\_CC\_PolicyTemplate: 0x190
  -TPM2\_CC\_PolicyTicket: 0x172
  -TPM2\_CC\_PP\_Commands: 0x12d
  -TPM2\_CC\_Quote: 0x158
  -TPM2\_CC\_ReadClock: 0x181
  -TPM2\_CC\_ReadPublic: 0x173
  -TPM2\_CC\_Rewrap: 0x152
  -TPM2\_CC\_RSA\_Decrypt: 0x159
  -TPM2\_CC\_RSA\_Encrypt: 0x174
  -TPM2\_CC\_SelfTest: 0x143
  -TPM2\_CC\_SequenceComplete: 0x13e
  -TPM2\_CC\_SequenceUpdate: 0x15c
  -TPM2\_CC\_SetAlgorithmSet: 0x13f
  -TPM2\_CC\_SetCommandCodeAuditStatus: 0x140
  -TPM2\_CC\_SetPrimaryPolicy: 0x12e
  -TPM2\_CC\_Shutdown: 0x145
  -TPM2\_CC\_Sign: 0x15d
  -TPM2\_CC\_StartAuthSession: 0x176
  -TPM2\_CC\_Startup: 0x144
  -TPM2\_CC\_StirRandom: 0x146
  -TPM2\_CC\_TestParms: 0x18a
  -TPM2\_CC\_Unseal: 0x15e
  -TPM2\_CC\_Vendor\_TCG\_Test: 0x20000000
  -TPM2\_CC\_VerifySignature: 0x177
  -TPM2\_CC\_ZGen\_2Phase: 0x18d

# EXAMPLES

Add TPM2_CC_Unseal to the list of audited commands.

```bash
tpm2_setcommandauditstatus TPM2_CC_Unseal
```

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
