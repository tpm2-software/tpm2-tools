% tpm2_getekcertificate(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_getekcertificate**(1) - Retrieve the Endorsement key Certificate for the TPM
endorsement key from the TPM manufacturer's endorsement certificate hosting
server.

# SYNOPSIS

**tpm2_getekcertificate** [*OPTIONS*] _URL_

# DESCRIPTION

**tpm2_getekcertificate**(1) - Retrieve the Endorsement key Certificate for
the TPM endorsement key from the TPM manufacturer's endorsement certificate hosting
server. The argument _URL_ specifies the address for the ek certificate portal.

# OPTIONS

  * **-E**, **\--ec-cert**=_EK\_CERTIFICATE\_FILE_:

    Specifies the file used to save the Endorsement key certificate retrieved from
    the TPM manufacturer provisioning server. Defaults to stdout if not
    specified.

  * **-U**, **\--untrusted**:

    Specifies to attempt connecting with the TPM manufacturer provisioning server
    without verifying server certificate.

    **WARNING**: This option should be used only on platforms with older CA certificates.

  * **-o**, **\--output**: _EK\_PUBLIC\_FILE_

    Specifies the file path for the endorsement key public portion in tss format.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

[supported public object algorithms](common/object-alg.md)

[algorithm specifiers](common/alg.md)

# NOTES

When the verbose option is specified, additional curl debugging information is
provided by setting the curl mode verbose, see
<https://curl.haxx.se/libcurl/c/CURLOPT_VERBOSE.html> for more information.

# EXAMPLES

```
tpm2_getekcertificate -U -E ECcert.bin -o ek.pub https://tpm.manufacturer.com/ekcertserver/

```

[returns](common/returns.md)

[footer](common/footer.md)
