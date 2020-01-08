## Changelog

### 3.2.2-RC0 - 2020-01-8
  * Update to work with newer version of TSS.
  * Fix algorithm selection parsing for algs like sm3_sha256.

### 3.2.1 - 2019-10-10
 * Fix invalid memcpy when extracting ECDSA plain signatures.
 * Fix resource leak on FILE * in hashing routine.
 * Correct PCR logic to prevent memory corruption bug.
 * errata handler fix.
 
### 3.2.0 - 2019-06-19
* fix configure bug for linking against libmu.
* tpm2_changeauth: Support changing platform hierarchy auth.
* tpm2_flushcontext: Introduce new tool for flushing handles from the TPM.
* tpm2_checkquote: Introduce new tool for checking validity of quotes.
* tpm2_quote: Add ability to output PCR values for quotes.
* tpm2_makecredential: add support for executing tool off-TPM.
* tpm2_pcrreset: introduce new tool for resetting PCRs.
* tpm2_quote: Fix AK auth password not being used.

### 3.1.4 - 2019-03-14
  * Fix various man pages
  * tpm2_getmanufec: fix OSSL build warnings
  * Fix broken -T option
  * Various build compatibility fixes
  * Fix some unit tests
  * Update build for recent autoconf-archive versions
  * Install m4 files

### 3.1.3 - 2018-10-15
  * Restore support for the TPM2TOOLS_* env vars for TCTI configuration, in
  addition to supporting the new unified TPM2TOOLS_ENV_TCTI
  * Fix tpm2_getcap to print properties with the TPM_PT prefix, rather than
  TPM2_PT
  * Make test_tpm2_activecredential Python 3 compatible
  * Fix tpm2_takeownership to only attempt to change the specified hierarchies

### 3.1.2 - 2018-08-14
  * Revert the change to use user supplied object attributes exclusively. This is an inappropriate behavioural change for a MINOR version number increment.
  * Fix inclusion of object attribute specifiers section in tpm2_create and tpm2_createprimary man pages.
  * Use better object attribute defaults for authentication, preventing an empty password being used for authentication when a policy is set.

### 3.1.1 - 2018-07-09
  * Allow man page installation without pandoc being available

### 3.1.0 - 2018-06-21
  * Update to use TSS version 2.0
  * When user supplies nv attributes use those exclusively, not in addition to the defaults
  * When user supplies object attributes use those exclusively, not in addition to the defaults
  * Load TCTI's by SONAME, not raw .so file

### 3.0.4 - 2018-05-30
  * Fix save and load for TPM2B_PRIVATE object.
  * Use a default buffer size for tpm2_nv{read,write} if the TPM reports a 0 size.
  * Fix --verbose and --version options crossover.
  * Generate man pages from markdown and include them in the distribution tarball.
  * Print usage summary if tools are executed with no options or man page can't be displayed.

### 3.0.3 - 2017-15-18
  * Tools that don't need a TPM to work no longer request
    a TPM connection. Namely, tpm2_rc_decode
  * Fix undefined references in libmarshal port.
### 3.0.2 - 2017-12-18
  * configure: enable code coverage option.
  * build: enable silent rules options.
  * Add system tests to dist tarball.
  * tpm2_nv(read|write): fix buffer overflows.

### 3.0.1 - 2017-12-11
  * Makefile: add missing LICENSE and markdown files.
### 3.0 - 2017-12-08
  * tpm2_getmanufec: -O as a flag for -f has changed. -O is for existing EK public structure
      and -f is only for generated EK public output.
  * tpm2_nvlist: output in yaml format.
  * tpm2_makecredential format changes to the -o output file.
  * tpm2-quote: -o option removed.
  * tpm2_rsaencrypt: -I is now an argument and input defaults to stdin. -o is optional and
    defaults to stdout.
  * tpm2_listpersistent: output friendly object attributes.
  * tpm2_createprimary: support friendly object attributes via -A. -H becomes auth
    hierarchy.
  * tpm2_create: support friendly object attributes via -A.
  * tpm2_nvwrite and tpm2_nvread have support for satisfying PCR policies.
  * tpm2_encryptdecrypt: has support for EncryptDecrypt2 command.
  * tpm2_nvwrite: -f option removed, support for stdin data supported. Support for starting
      index to write to.
  * errata framework added for dealing with spec errata.
  * tpm2_quote: -G option for signature hash algorithm specification.
  * tpm2_dump_capability: renamed to tpm2_getcap.
  * tpm2_send_command: renamed to tpm2_send and the input file is now an
    argument vs using -i.
  * tpm2_dump_capability: outputs human readable command codes.
  * camelCase options are now all lower case. For example, --camelCase becomes --camel-case.
  * tpm2_quote,readpublic, and sign now have support for pem/der output/inputs. See the
    respective man pages for more details.
  * tpm2_nvread: Has an output file option, -f.
  * manpages: Are now in Markdown and converted to roff using pandoc.
  * tpm2_create - options 'o' and 'O' changed to 'u' and 'r' respectively. 
  * tpm2_pcrlist: support yaml output for parsing.
  * tpm2_pcrevent: new tool for hashing and extending pcrs.
  * Make tpm2_{createprimary,create,load,pcrlist,hmac} tools to support the --quiet option.
  * Support for a --quiet option to suppress messages printed by tools to standard output.
  * tpm2_hmac: support for files greater than 1024 bytes, changes in options and arguments.
  * tpm2_hash: support for files greater than 1024 bytes, changes in options and arguments.
  * Install is now to bin vs sbin. Ensure that sbin tools get removed!
  * make dist and distcheck are now working.
  * installation into customized locations are now working, see issue #402 for details.
  * tpm2_pcrlist: renamed from tpm2_listpcrs.
  * tpm2_pcrextend: new tool for extending PCRs.
  * tpm2_getmanufec: -E option no longer required, defaults to stdout.
  * tpm2_nvlist: Support for friendly nv attributes in output.
  * Support for friendly algorithm names for algorithm identifiers.
  * tpm2_nvread: The option, -s, or size option is no longer required.
  * tpm2_nvwrite: fixed to write files larger than 1024 in size.
  * tpm2_nvread: fixed to read files larger than 1024 in size.
  * tpm2_nvdefine supports "nice-names" for nv space attributes.
  * Support using PCR Policy directly with tpm2_unseal tool.
  * Support PCR policy creation in tpm2_createpolicy
  * Support using a policy session as input to tools that may need to satisfy complex policies
    other than password.
  * tpm2_unseal: supports output to stdoud.
  * tpm2_create: enforce policy based authorization.
  * tpm2_createprimary: add ability to create objects with policy based authorization.
  * tpm2_nvdefine: add ability to create nv indexes with policy based authorization.
  * Support Clang Build.
  * tpm2_unseal test uses endorsement hierarchy as platform hierarchy is unavailable on a
    real tpm.
  * Numerous cleanups and minor bug fixes.

### v2.0 - 2017-03-29

  * Tracked on the milestone: https://github.com/01org/tpm2-tools/milestone/2
  * Reworked all the tools to support configurable TCTIs, based on build time
    configuration, one can specify the tcti via the --tcti (-T) option to all
    tools.
  * tpm2_getrandom interface made -s a positional argument.
  * Numerous bug fixes.

### v1.1 - 2016-11-04

  * travis ci support.
  * Allow for unit tests to be enabled selectively.
  * tpm2_rc_decode tool: Decode TPM_RC error codes.
  * Android Make file
  * tpm2_listpersistent: list all persistent objects
  * test scripts for tpm2-tools
  * tpm2_nvreadlock
  * tpm2_getmanufec: retrieve EC from tpm manufacturer server.
  * Copy 'common' and 'sample' code from the TPM2.0-TSS repo.

  **Modified**

  * tpm2_takeownership: update option -c to use lockout password to clear.
  * tpm2_listpcrs: add options -L and -s, rewrite to increase performance.
  * tpm2_quote: added -L option to support selection of multiple banks.
  * tpm2_quote: add -q option to get qualifying data.
  * configure: Use pkg-config to get info about libcurl and libcrypto.
  * configure: Use pkg-config to locate SAPI and TCTI headers / libraries.
  * tpm2_x: Add -X option to enable password input in Hex format.
  * tpm2_nvdefine: Change -X option to -I.
  * tpm2-nvwrite: fix for unable to write 1024B+ data.
  * tpm2_getmanufec: Fix base64 encoding.
  * tpm2_x: fixed a lot of TPM2B failures caused by wrong initialization.
  * tpm2_getmanufec: let configure handle libs.
  * tpm2_getmanufec: Convert from dos to unix format.
  * build: Check for TSS2 library @ configure time.
  * build: Detect required TSS2 and TCTI headers.
  * build: Use libtool to build the common library
  * build: Install all binaries into sbin.
  * build: Build common sources into library.
  * build: Move all source files to 'src'.
  * Makefile.am: Move all build rules into single Makefile.am.
  * everything: Use new TCTI headers and fixup API calls.
  * everything: Update source to cope with sapi header cleanup.
  * tpm2_activatecredential: Updated to support TCG compatible EK
  * tpm2_getpubak: Updated to use TCG compatible EK
  * tpm2_getpubek: fix ek creation to follow TCG EK profile spec.

  **Removed**

  * Windows related code
  * depenedency on the TPM2.0-TSS repo source code

### v1.0 - 2015-10-19

  * 1.0 release
  * 29 tools included
