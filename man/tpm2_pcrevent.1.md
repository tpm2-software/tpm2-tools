% tpm2_pcrevent(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_pcrevent**(1) - Hashes a file and optionally extends a pcr.

# SYNOPSIS

**tpm2_pcrevent** [*OPTIONS*] _FILE_

# DESCRIPTION

**tpm2_pcrevent**(1) - Hashes _FILE_ if specified or stdin. It uses all of the
hashing algorithms that the TPM supports.

Optionally, if a PCR index is specified, it extends that PCR for all
supported algorithms with the hash digest. In either case, it
outputs to stdout the hash algorithm used and the digest value,
one per line:

_alg_:_digest_

Where _alg_ is the algorithm used (like sha1) and _digest_ is the digest
resulting from the hash computation of _alg_ on the data.

See sections 23.1 and sections 17 of the [TPM2.0 Specification](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf)

# OPTIONS

These options control extending the pcr:

  * **-x**, **--pcr-index**=_INDEX_:

    Not only compute the hash digests on _FILE_, also extend the PCR given by
    _INDEX_ for all supported hash algorithms.

  * **-P**, **--auth-pcr**=_PCR\_AUTH_:

    Specifies the authorization value for PCR. Authorization values
    should follow the "authorization formatting standards", see section
    "Authorization Formatting".

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

# EXAMPLES

## Hash a file
```
tpm2_pcrevent data
```

## Hash a file and extend PCR 8
```
tpm2_pcrevent -x 8 data
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
