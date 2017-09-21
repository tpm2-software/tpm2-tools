tpm2_getmanufec 1 "AUGUST 2017" tpm2-tools
==================================================

NAME
----

tpm2_getmanufec(1) - Retrieve the Endorsement Credential Certificate for the TPM
endorsement key from the TPM manufacturer's endorsement certificate hosting
server.

SYNOPSIS
--------

`tpm2_getmanufec` [OPTIONS]

DESCRIPTION
-----------

tpm2_getmanufec(1) - Retrieve the Endorsement Credential Certificate for the TPM
endorsement key from the TPM manufacturer's endorsement certificate hosting
server.

OPTIONS
-------

  * `-e`, `--endorsePasswd`=_ENDORSE\_PASSWORD_:
    specifies current endorse password (string, optional,default:NULL).

  * `-o`, `--ownerPasswd`=_OWNER\_PASSWORD_:
    specifies current owner password (string, optional,default:NULL).

  * `-P`, `--ekPasswd`=_EK\_PASSWORD_:
    specifies the EK password when created (string,optional,default:NULL).

  * `-H`, `--handle`=_HANDLE_:
    specifies the handle used to make EK  persistent (hex).

  * `-g`, `--alg`=_ALGORITHM_:
    specifies the algorithm type of EK.
    See section "Supported Public Object Algorithms" for a list of supported
    object algorithms. See section "Algorithm Specifiers" on how to specify
    an algorithm argument.

  * `-f`, `--file`=_FILE_:
    specifies the file used to save the public portion of EK.

  * `-N`, `--NonPersistent`:
    specifies to readout the EK public without making it persistent.

  * `-O`, `--OfflineProv`:
    specifies that the file specifier from `-f` is an EK retrieved from offline
    platform that needs to be provisioned.

  * `-E`, `--ECertFile`=_EC\_CERT\_FILE_:
    Specifies the file used to save the Endorsement Credentials retrieved from
    the TPM manufacturer provisioning server. Defaults to stdout if not
    specified.

  * `-S`, `--EKserverAddr`=_SERVER\_ADDRESS_:
    specifies to attempt retrieving the Endorsement Credentials from the
    specified   TPM manufacturer provisioning server.

  * `-U`, `--SSL_NO_VERIFY`:
    specifies to attempt connecting with the  TPM manufacturer provisioning server
    with SSL_NO_VERIFY option.

  * `-X`, `--passwdInHex`:
    passwords given by any options are hex format.

  * `-i`, `--input-session-handle`=_SESSION\_HANDLE_:
    Optional Input session handle from a policy session for authorization.


[common options](common/options.md)

[common tcti options](common/tcti.md)

[supported public object algorithms](common/object-alg.md)

[algorithm specifiers](common/alg.md)

NOTES
-----

When the verbose option is specified, additional curl debugging information is
provided by setting the curl mode verbose, see:
<https://curl.haxx.se/libcurl/c/CURLOPT_VERBOSE.html> for more information.

EXAMPLES
--------
```
tpm2_getmanufec -e abc123 -o abc123 -P passwd -H 0x81010001-g 0x01 -O -N -U -E ECcert.bin -f ek.bin -S https://tpm.manufacturer.com/ekcertserver/ 
tpm2_getmanufec -e 1a1b1c -o 1a1b1c -P 123abc -X -H 0x81010001-g 0x01 -O -N -U -E ECcert.bin -f ek.bin -S https://tpm.manufacturer.com/ekcertserver/ 
```

RETURNS
-------
0 on success or 1 on failure.

BUGS
----
[Github Issues](https://github.com/01org/tpm2-tools/issues)

HELP
----
See the [Mailing List](https://lists.01.org/mailman/listinfo/tpm2)

