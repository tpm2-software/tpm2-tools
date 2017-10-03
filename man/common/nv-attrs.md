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
**TPMA_NV_OWNERWRITE**, **TPMA_NV_POLICYWRITE**, and **TPMA_NT = 0x3**, the argument
would be:

**ownerread|ownerwrite|policywrite|nt=0x3**