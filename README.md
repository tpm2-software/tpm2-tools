[![Build Status](https://travis-ci.org/01org/tpm2-tools.svg?branch=master)](https://travis-ci.org/01org/tpm2-tools)
<a href="https://scan.coverity.com/projects/01org-tpm2-tools">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/13105/badge.svg"/>
</a>
[![Coverage Status](https://coveralls.io/repos/github/01org/tpm2-tools/badge.svg?branch=coveralls)](https://coveralls.io/github/01org/tpm2-tools?branch=coveralls)

**This site contains the code for the TPM (Trusted Platform Module) 2.0 tools based on tpm2-tss**

## News
* Release 2.1.0 is now available: https://github.com/01org/tpm2-tools/releases/tag/2.1.0
* A mailing list now exists for support: https://lists.01.org/mailman/listinfo/tpm2
* CVE-2017-7524 - Where an HMAC authorization uses the tpm to perform the hmac calculation. This results in a disclosure of the password to
the tpm where the user would not expect it. It appears likely unreachable in the current code base. This has been fixed on releases greater than version 1.1.1.

## Build and Installation instructions:
Instructions for building and installing the tpm2-tools are provided in the [INSTALL](https://github.com/01org/tpm2-tools/blob/master/INSTALL) file.

**For more details on this code and how to use it, the [manual](https://github.com/01org/tpm2-tools/blob/master/manual) file is a good place to start.**

## Support
Please use the mailing list at https://lists.01.org/mailman/listinfo/tpm2 for general questions. The Issue Tracker on
github should be reserved for actual feature requests or bugs.

## Resources
TPM 2.0 specifications can be found at [Trusted Computing Group](http://www.trustedcomputinggroup.org/).

## Contributing
Instructions for contributing to the project are provided in the [CONTRIBUTING](https://github.com/01org/tpm2-tools/blob/master/CONTRIBUTING) file.

