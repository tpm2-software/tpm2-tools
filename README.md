**This site contains the code for the TPM (Trusted Platform Module) 2.0 tools based on TPM2.0-TSS**

Below is the name list of the implemented tools:
##Subset 1: NV tools
tpm2_nvdefine
tpm2_nvrelease
tpm2_nvread
tpm2_nvwrite
tpm2_nvlist
##Subset 2: Attestation tools
tpm2_takeownership
tpm2_getpubek
tpm2_getpubak
tpm2_akparse
tpm2_makecredential
tpm2_activatecredential
tpm2_listpcrs
tpm2_quote
##Subset 3: Key management tools
tpm2_createprimary
tpm2_create
tpm2_evictcontrol
tpm2_load
tpm2_loadexternal
##Subset 4: Encryption tools
tpm2_encryptdecrypt
tpm2_rsaencrypt
tpm2_rsadecrypt
tpm2_unseal
##Subset 5: Signing tools
tpm2_sign
tpm2_verifysignature
tpm2_certify
##Subset 6: utilities
tpm2_getrandom
tpm2_hash
tpm2_hmac
tpm2_readpublic

## Build and Installation instructions:
Instructions for building and installing the tpm2.0-tools are provided in the [INSTALL](https://github.com/01org/tpm2.0-tools/blob/master/INSTALL) file.

**For more details on this code and how to use it, the [manual](https://github.com/01org/tpm2.0-tools/blob/master/manual) file is a good place to start.**

## Resources
TPM 2.0 specifications can be found at [Trusted Computing Group](http://www.trustedcomputinggroup.org/).

