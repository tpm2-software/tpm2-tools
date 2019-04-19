# Object Attributes

Object Attributes are used to control various properties of created objects.
When specified as an option, either the raw bitfield mask or "nice-names" may be
used. The values can be found in Table 31 Part 2 of the TPM2.0 specification,
which can be found here:

<https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf>

Nice names are calculated by taking the name field of table 31 and removing the
prefix **TPMA_OBJECT_** and lowercasing the result. Thus, **TPMA_OBJECT_FIXEDTPM** becomes
fixedtpm. Nice names can be joined using the bitwise or "|" symbol.

For instance, to set The fields **TPMA_OBJECT_FIXEDTPM**,
**TPMA_OBJECT_NODA**, and **TPMA_OBJECT_SIGN_ENCRYPT**, the argument
would be:

**fixedtpm|noda|sign**
