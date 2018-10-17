[![Build Status](https://travis-ci.org/tpm2-software/tpm2-tools.svg?branch=master)](https://travis-ci.org/tpm2-software/tpm2-tools)
[![Coverity Scan](https://img.shields.io/coverity/scan/3997.svg)](https://scan.coverity.com/projects/01org-tpm2-0-tools)
[![Coverage Status](https://coveralls.io/repos/github/tpm2-software/tpm2-tools/badge.svg?branch=master)](https://coveralls.io/github/tpm2-software/tpm2-tools?branch=master)

**This site contains the code for the TPM (Trusted Platform Module) 2.0 tools based on tpm2-tss**

## News
* Release [3.1.3](https://github.com/tpm2-software/tpm2-tools/releases/tag/3.1.3) is now available.
* A mailing list now exists for support: https://lists.01.org/mailman/listinfo/tpm2
* CVE-2017-7524 - Where an HMAC authorization uses the tpm to perform the hmac calculation. This results in a disclosure of the password to
the tpm where the user would not expect it. It appears likely unreachable in the current code base. This has been fixed on releases greater than version 1.1.1.

## Build and Installation instructions:
Instructions for building and installing the tpm2-tools are provided in the [INSTALL.md](INSTALL.md) file.

## Release Procedures
Instructions for how releases are conducted, including our QA practices, please see the [RELEASE.md](RELEASE.md) file.

## Support
Please use the mailing list at https://lists.01.org/mailman/listinfo/tpm2 for general questions. The Issue Tracker on
github should be reserved for actual feature requests or bugs. For security bugs, please see [CONTRIBUTING.md](CONTRIBUTING.md)
for information on how to submit those.

## Resources

The tpm2-tools wiki:
<https://github.com/tpm2-software/tpm2-tools/wiki>

TPM 2.0 specifications can be found at [Trusted Computing Group](http://www.trustedcomputinggroup.org/).

Specifically, the following sections:

### The Library Specification
This specifies the external programatic interface to the TPM:
<https://trustedcomputinggroup.org/tpm-library-specification/>

### The Enhanced System API Specification
This is the *ESAPI* dependency mentioned in [INSTALL.md](INSTALL.md). This is the enhanced software API to the tpm. The tpm2-tools
project relies heavily on this. <https://trustedcomputinggroup.org/wp-content/uploads/TSS_ESAPI_Version-0.9_Revision-04_reviewEND030918.pdf>

### The TCTI Specification
This specifies the transmission interfaces or how bytes get from the system api to the tpm.
<https://trustedcomputinggroup.org/wp-content/uploads/TSS_TCTI_v1.0_r04_Public-Review.pdf>

### Books
  * [A Practical Guide to TPM 2.0](https://link.springer.com/book/10.1007%2F978-1-4302-6584-9) `ISBN: 978-1-4302-6583-2 (Print) 978-1-4302-6584-9 (Online)`

## Contributing
Instructions for contributing to the project are provided in the [CONTRIBUTING.md](CONTRIBUTING.md) file.
