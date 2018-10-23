## Changelog
### next
  * Ported all tools from SAPI to ESAPI
  * tpm2_loadexternal: support OSSL style -passin argument as --passin for PEM file passwords.
  * tpm2_import: support OSSL style -passin argument as --passin for PEM file passwords.
  * tpm2_readpublic: supports ECC pem and der file generation.
  * tpm2_activatecredential: Option `--endorse-passwd` changes to `--auth-endorse`.
  * tpm2_loadexternal: name output to file and stdout. Changes YAML stdout output.
  * tpm2_loadexternal: ECC Public and Private PEM support.
  * tpm2_loadexternal: AES Public and Private "raw file" support.
  * tpm2_loadexternal: RSA Public and Private PEM support.
  * tpm2_loadexternal: Object Attribute support.
  * tpm2_loadexternal: Object authorization support.
  * tpm2_loadexternal: Default hierarchy changes to the *null* hierarchy.
  * tpm2_verifysignature: stop outputting message hash.
  * tpm2_verifysignature: issues a warning when ticket is specified for a NULL hierarchy.
  * tpm2_verifysignature: make -t optional.
  * tpm2_import: support additional import key types:
    * RSA1024/2048
    * AES128/192/256
  * tpm2_import: -q changes to -u to align with tpm2_loads public/private output arguments.
  * tpm2_import: Supports setting object name algorithm via -g.
  * tpm2_unseal: -P becomes -p
  * tpm2_sign: -P becomes -p
  * tpm2_nvreadlock: long form for -P is now --auth-hierarchy
  * tpm2_rsadecrypt: -P becomes -p
  * tpm2_nvrelease: long-form of -P becomes --auth-hierarchy
  * tpm2_nvdefine: -I becomes -p
  * tpm2_encryptdecrypt: -P becomes -p
  * tpm2_dictionarylockout: -P becomes -p
  * tpm2_createprimary: -K becomes -p
  * tpm2_createak: -E becomes -e
  * tpm2_certify: -k becomes -p
  * tpm2_hash: -g changes to -G
  * tpm2_encryptdecrypt: Support IVs via -i and algorithm modes via -G.
  * tpm2_hmac: drop -g, just use the algorithm associated with the object.
  * tpm2_getmanufec: -g changes to -G
  * tpm2_createek: -g changes to -G
  * tpm2_createak: -g changes to -G
  * tpm2_verifysignature: -g becomes -G
  * tpm2_sign: -g becomes -G
  * tpm2_import: support specifying parent key with a context file,
    --parent-key-handle/-H becomes --parent-key/-C
  * tpm2_nvwrite and tpm2_nvread: when -P is "index" -a is optional and defaults to
    the NV_INDEX value passed to -x.
  * Load TCTI's by SONAME, not raw .so file
  * tpm2_activatecredential: -e becomes -E
  * tpm2_activatecredential: -e becomes -E
  * tpm2_certify: -c and -C are swapped, -k becomes -K
  * tpm2_createprimary: -K becomes -k
  * tpm2_encryptdecrypt: supports input and output to stdin and stdout respectively.
  * tpm2_create: -g/-G become optional options.
  * tpm2_createprimary: -g/-G become optional options.
  * tpm2_verifysignature - Option `-r` changes to `-f` and supports signature format "rsa".
  * tpm2_import - Parent public data option, `-K` is optional.
  * tpm2_import - Supports importing external RSA 2048 keys via pem files.
  * tpm2_pcrlist: Option `--algorithm` changes to `--halg`, which is in line with other tools.
  * tpm2_verifysignature: Option `-r` and `--raw` have been removed. This were unused within the tool.
  * tpm2_hmac: Option `--algorithm` changes to `--halg`, which is in line with the manpage.
  * tpm2_makecredential: Option `--sec` changes to `--secret`.
  * tpm2_activatecredential: Option `--Password` changes to `--auth-key`.
  * system tests are now run with make check when --enable-unit is used in configure.
  * tpm2_unseal: Option `--pwdk` changes to `--auth-key`.
  * tpm2_sign: Option `--pwdk` changes to `--auth-key`.
  * tpm2_rsadecrypt: Option `--pwdk` changes to `--auth-key`.
  * tpm2_quote: Option `--ak-passwd` changes to `--auth-ak`
  * tpm2_pcrevent: Option `--passwd` changes to `--auth-pcr`
  * tpm2_nvwrite: Options `--authhandle` and `--handle-passwd`
    changes to `--hierarchy` and `--auth-hierarchy` respectively.
  * tpm2_nvread: Options `--authhandle` and `--handle-passwd`
    changes to `--hierarchy` and `--auth-hierarchy` respectively.
  * tpm2_nvdefine: Options `--authhandle`, `--handle-passwd` and `--index-passwd`
    changes to `--hierarchy`, `--auth-hierarchy` and `--auth-index`
    respectively.
  * tpm2_loadexternal: `-H` changes to `-a` for specifying hierarchy.
  * tpm2_load: Option `--pwdp` changes to `--auth-parent`.
  * tpm2_hmac: Option `--pwdk` changes to `--auth-key`.
  * tpm2_hash: `-H` changes to `-a` for specifying hierarchy.
  * tpm2_getmanufec: Options `--owner-passwd`, `--endorse-passwd`
  * and `--ek-passwd`change to `--auth-owner`, `--auth-endorse`
    and `--auth-ek` respectively.
  * tpm2_evictcontrol: Option group `-A` and `--auth` changes to `-a` and `--hierarchy`
    Option `--pwda` changes to `--auth-hierarchy`
  * tpm2_encryptdecrypt: Option `--pwdk` changes to `--auth-key`.
  * tpm2_dictionarylockout: Option `--lockout-passwd` changes to `--auth-lockout`
  * tpm2_createprimary: Options `--pwdp` and `--pwdk` change to
    `--auth-hierarchy` and `--auth-object` respectively.
  * tpm2_createek: Options `--owner-passwd`, `--endorse-passwd`
  * and `--ek-passwd`change to `--auth-owner`, `--auth-endorse`
    and `--auth-ek` respectively.
  * tpm2_createak: Options `--owner-passwd`, `--endorse-passwd`
  * and `--ak-passwd`change to `--auth-owner`, `--auth-endorse`
    and `--auth-ak` respectively.
  * tpm2_create: Options `--pwdo` and `--pwdk` change to `--auth-object` and
    `--auth-key` respectively.
  * tpm2_clearlock: Option `--lockout-passwd` changes to `--auth-lockout`
  * tpm2_clear: Option `--lockout-passwd` changes to `--auth-lockout`
  * tpm2_changeauth: Options, `--old-owner-passwd`, `--old-endorse-passwd`,
    and `--old-lockout-passwd` go to `--old-auth-owner`, `--old-auth-endorse`,
    and `--old-auth-lockout` respectively.
  * tpm2_certify: Options `--pwdo` and `--pwdk` change to `--auth-object` and
    `--auth-key` respectively.
  * tpm2_createprimary: `-H` changes to `-a` for specifying hierarchy.
  * tpm2_createak: support for non-persistent AK generation.
  * tpm2_createek: support for non-persistent EK generation.
  * tpm2_getpubak renamed to tpm2_createak, -f becomes -p and -f is used for format of public key
    output.
  * tpm2_getpubek renamed to tpm2_createek, -f becomes -p and -f is used for format of public key
    output.
  * Libre SSL builds fixed.
  * Dynamic TCTIS. Support for pluggable TCTI modules via the -T or --tcti options.
  * tpm2_sign: supports signing a pre-computed hash via -D
  * tpm2_clearlock: tool added
  * test: system testing scripts moved into subordinate test directory.
  * fix a buffer overflow in nvread/write tools.
  * configure: enable code coverage option.
  * tpm2_takeownership: split into tpm2_clear and tpm2_changeauth
  * env: add TPM2TOOLS_ENABLE_ERRATA to control the -Z or errata option.

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

  * Tracked on the milestone: https://github.com/tpm2-software/tpm2-tools/milestone/2
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
  * dependency on the TPM2.0-TSS repo source code

### v1.0 - 2015-10-19

  * 1.0 release
  * 29 tools included
