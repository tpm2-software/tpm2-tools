# NV Attributes

NV Attributes are used to control various properties of the NV defined space.
When specified as an option, either the raw bitfield mask or "nice-names" may be
used. The values can be found in Table 204 Part 2 of the TPM2.0 specification,
which can be found here:

<https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf>

Nice names are calculated by taking the name field of table 204 and removing the
prefix **TPMA_NV_** and lowercasing the result. Thus, **TPMA_NV_PPWRITE** becomes
ppwrite. Nice names can be joined using the bitwise or "|" symbol.

Note that the **TPM_NT** field is 4 bits wide, and thus can be set via
**nt=<num>** format. For instance, to set The fields **TPMA_NV_OWNERREAD**,
**TPMA_NV_OWNERWRITE**, **TPMA_NV_POLICYWRITE**, and **TPMA_NT = 0x2**, the argument
would be:

**ownerread|ownerwrite|policywrite|nt=0x2**

Additionally, the NT field, which denotes the type of the NV index, can also be specified
via friendly names:
  * ordinary - Ordinary contains data that is opaque to the TPM that can
      only be modified using TPM2\_NV\_Write.
  * extend - Extend is used similarly to a PCR and can only be modified
      with TPM2_NV_Extend. Its size is determined by the length of the hash
      algorithm used.
  * counter - Counter contains an 8-octet value that is to be used as a
      counter and can only be modified with TPM2\_NV\_Increment
  * bits - Bit Field contains an 8-octet value to be used as a bit field
      and can only be modified with TPM2\_NV\_SetBits.
  * pinfail - PIN Fail contains an 8-octet pinCount that increments on a PIN authorization failure and a pinLimit.
  * pinpass - PIN Pass contains an 8-octet pinCount that increments on a PIN authorization success and a pinLimit.

For instance, to set The fields **TPMA_NV_OWNERREAD**,
**TPMA_NV_OWNERWRITE**, **TPMA_NV_POLICYWRITE**, and **TPMA_NT = bits**, the argument
would be:

**ownerread|ownerwrite|policywrite|nt=bits**
