tpm2_pcrevent 1 "AUGUST 2017" tpm2-tools
==================================================

NAME
----

tpm2_pcrevent(1) - hashes a file and optionally extends a pcr.

SYNOPSIS
--------

`tpm2_pcrevent` [OPTIONS] [_FILE_]

DESCRIPTION
-----------

tpm2_pcrevent(1) hashes _FILE_ if specified or stdin. It uses all of the
hashing algorithms that the tpm supports. Optionally, if a pcr index is
specified, it extends that pcr for all supported algorithms with the hash
digest. In either case, it outputs to stdout the hash algorithm used and the
digest value, one per line:

_alg_:_digest_

Where _alg_ is the algorithm used (eg. sha1) and _digest_ is the digest
resulting from the hash computation of _alg_ on the data.

See sections 23.1 and sections 17 of the [TPM2.0 Specification](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf)

OPTIONS
-------

These options control extending the pcr:

  * `-i`, `--pcr-index`=_INDEX_:
    Not only compute the hash digests on _FILE_, also extend the pcr given by
    _INDEX_ for all supported hash algorithms.

  * `-S`, `--input-session-handle`=_SESSION_HANDLE_:
    Use _SESSION_HANDLE_ for providing an authorization session for the pcr
    specified by _INDEX_.
    It is an error to specify `-S` without specifying a pcr index with `-i`.

  * `-P`, `--password`=_PASSWORD_:
    Use _PASSWORD_ for providing an authorization value for the pcr specified
    in _INDEX_.
    It is an error to specify `-P` without specifying a pcr index with `-i`.

[common options](common/options.md)

[common tcti options](common/tcti.md)

EXAMPLES
--------

Hash a file:

tpm2_pcrevent data

Hash a file and extend pcr 8:

tpm2_pcrevent -i 8 data

RETURNS
-------
0 on success or 1 on failure.

BUGS
----
[Github Issues](https://github.com/01org/tpm2-tools/issues)

HELP
----
See the [Mailing List](https://lists.01.org/mailman/listinfo/tpm2)

