[![Build Status](https://travis-ci.org/01org/tpm2.0-tools.svg?branch=master)](https://travis-ci.org/01org/tpm2.0-tools)

**This site contains the code for the TPM (Trusted Platform Module) 2.0 tools based on TPM2.0-TSS**

## News
CVE-2017-7524 - Where an HMAC authorization uses the tpm to perform the hmac calculation. This results in a disclosure of the password to the tpm
where the user would not expect it. It appears likely unreachable in the current code base.

This has been fixed on master and a release on version 1.X will occur shortly.

## Build and Installation instructions:
Instructions for building and installing the tpm2.0-tools are provided in the [INSTALL](https://github.com/01org/tpm2.0-tools/blob/master/INSTALL) file.

**For more details on this code and how to use it, the [manual](https://github.com/01org/tpm2.0-tools/blob/master/manual) file is a good place to start.**

## Resources
TPM 2.0 specifications can be found at [Trusted Computing Group](http://www.trustedcomputinggroup.org/).

## Contributing
Instructions for contributing to the project are provided in the [CONTRIBUTING](https://github.com/01org/tpm2.0-tools/blob/master/CONTRIBUTING) file.

