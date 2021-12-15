[![Build Status](https://github.com/tpm2-software/tpm2-tools/workflows/CI/badge.svg)](https://github.com/tpm2-software/tpm2-tools/actions)
[![FreeBSD Build Status](https://api.cirrus-ci.com/github/tpm2-software/tpm2-tools.svg?branch=master)](https://cirrus-ci.com/github/tpm2-software/tpm2-tools)
[![codecov](https://codecov.io/gh/tpm2-software/tpm2-tools/branch/master/graph/badge.svg)](https://codecov.io/gh/tpm2-software/tpm2-tools)
[![Coverity Scan](https://img.shields.io/coverity/scan/3997.svg)](https://scan.coverity.com/projects/01org-tpm2-0-tools)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/tpm2-software/tpm2-tools.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/tpm2-software/tpm2-tools/context:cpp)

**This site contains the code for the TPM (Trusted Platform Module) 2.0 tools based on tpm2-tss**

## Build and Installation instructions:
Instructions for building and installing the tpm2-tools are provided in the [INSTALL.md](INSTALL.md) file.

## Release Procedures
Instructions for how releases are conducted, including our QA practices, please see the [RELEASE.md](RELEASE.md) file.

## Support
Please use the mailing list at https://lists.01.org/postorius/lists/tpm2.lists.01.org/ for general questions. The Issue Tracker on
github should be reserved for actual feature requests or bugs. For security bugs, please see [CONTRIBUTING.md](CONTRIBUTING.md)
for information on how to submit those.

## Resources

Reference the tutorials at [tpm2-software.github.io](https://tpm2-software.github.io).

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
