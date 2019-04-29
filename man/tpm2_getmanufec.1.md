% tpm2_getmanufec(1) tpm2-tools | General Commands Manual
%
% AUGUST 2017

# NAME

**tpm2_getmanufec**(1) - Retrieve the Endorsement Credential Certificate for the TPM
endorsement key from the TPM manufacturer's endorsement certificate hosting
server.

# SYNOPSIS

**tpm2_getmanufec** [*OPTIONS*] _URL_

# DESCRIPTION

**tpm2_getmanufec**(1) - Retrieve the Endorsement Credential Certificate for
the TPM endorsement key from the TPM manufacturer's endorsement certificate hosting
server.

# OPTIONS

  * **-e**, **\--auth-endorse**=_ENDORSE\_AUTH_:

    Specifies current endorsement authorization.
    Authorizations should follow the "authorization formatting standards", see
    section "Authorization Formatting".

  * **-P**, **\--auth-ek**=_EK\_AUTH_

    Specifies the EK authorization when created.
    Same formatting as the endorse authorization value or **-e** option.

  * **-w**, **\--auth-owner**=_OWNER\_AUTH_

    Specifies the current owner authorization.
    Same formatting as the endorse authorization value or **-e** option.

  * **-H**, **\--handle**=_HANDLE_:

    Specifies the handle used to make EK  persistent.
    If a value of **-** is passed the tool will find a vacant persistent handle
    to use and print out the automatically selected handle.

  * **-G**, **\--algorithm**=_ALGORITHM_:

    Specifies the algorithm type of EK.
    See section "Supported Public Object Algorithms" for a list of supported
    object algorithms. See section "Algorithm Specifiers" on how to specify
    an algorithm argument.

  * **-o**, **\--out-file**=_FILE_:

    Specifies the file used to save the public portion of EK.

  * **-N**, **\--non-persistent**:

    Specifies to readout the EK public without making it persistent.

  * **-O**, **\--offline**=_FILE_:

    Specifies the file that contains an EK retrieved from offline
    platform that needs to be provisioned.

  * **-E**, **\--ec-cert**=_EC\_CERT\_FILE_:

    Specifies the file used to save the Endorsement Credentials retrieved from
    the TPM manufacturer provisioning server. Defaults to stdout if not
    specified.

  * **-U**, **\--untrusted**:

    Specifies to attempt connecting with the TPM manufacturer provisioning server
    without verifying server certificate.

    **WARNING**: This option should be used only on platforms with older CA certificates.

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
tpm2_getmanufec -e abc123 -w abc123 -P passwd -H 0x81010001 -G rsa -O -N -U -E ECcert.bin -o ek.bin https://tpm.manufacturer.com/ekcertserver/

tpm2_getmanufec -e 1a1b1c -w 1a1b1c -P 123abc -H 0x81010001 -G rsa -O -N -U -E ECcert.bin -o ek.bin https://tpm.manufacturer.com/ekcertserver/
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
