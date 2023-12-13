% tpm2_getekcertificate(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_getekcertificate**(1) - Retrieve the Endorsement key Certificate.

# SYNOPSIS

**tpm2_getekcertificate** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_getekcertificate**(1) - Retrieve the endorsement key certificate. The
certificate is present either on the TCG specified TPM NV indices OR on the TPM
manufacturer's endorsement certificate hosting server. Following are the
conditions dictating the certificate location lookup.

1. NV-Index:

    Default search location when **ARGUMENT** is not specified.

2. Intel-EK-certificate-server:

    Search location when EK certificate could not be found in the NV index AND
    tpmEPSgenerated bit is CLEAR AND manufacturer is INTC.

3. Intel-EK-Re-certification-server:

    Search location when EK certificate could not be found in the NV index AND
    tpmEPSgenerated bit is SET AND manufacturer is INTC.

    Note:

    In this operation information is provided regarding additional software to
    be run as part of the re-provisioning/ re-certification service.

    After re-provisioning/ recertification process is complete, EK certificates
    can be read from the NV indexes by running another instance of
    **tpm2_getekcertificate**.

4. Generic or other EK-certificate-server:

    Search location when **ARGUMENT** specifies the EK certificate web hosting
    address.

# OPTIONS

  * **-o**, **\--ek-certificate**=_FILE_ or _STDOUT_:

    The file to save the Endorsement key certificate. When EK certificates are
    found in the TPM NV indices, this option can be specified additional times
    to save the RSA and ECC EK certificates in order. The tool will warn if
    additional EK certificates are found on the TPM NV indices and only a single
    output file is specified. If the option isn't specified all the EK
    certificates retrieved either from the manufacturer web hosting or from the
    TPM NV indices, are output to stdout.

  * **-X**, **\--allow-unverified**:

    Specifies to attempt connecting with the TPM manufacturer provisioning
    server without verifying server certificate. This option is irrelevant when
    EK certificates are found on the TPM NV indices.

    **WARNING**: This option should be used only on platforms with older CA
    certificates.

  * **-u**, **\--ek-public**=_FILE_:

    Specifies the file path for the endorsement key public portion in tss
    format.

  * **-x**, **\--offline**:

    This flags the tool to operate in an offline mode. In that the certificates
    can be retrieved for supplied EK public that do not belong to the platform
    the tool is run on. Useful in factory provisioning of multiple platforms
    that are not individually connected to the Internet. In such a scenario a
    single Internet facing provisioning server can utilize this tool in this
    mode. This forces the tool to not look for the EK certificates on the NV
    indices.

  * **--raw**:

    This flags the tool to output the EK certificate as is received from the
    source: NV/ Web-Hosting.

  * **-E**, **\--encoding**=_ENCODING_:

    Specifies the encoding format to use explicitly. Normally, the default
    method is the one used by Intel unless an AMD fTPM is detected, in which
    case the AMD-specific encoding is used. Use 'a' for AMD and 'i' for Intel.

  * **ARGUMENT** the command line argument specifies the URL address for the EK
    certificate portal. This forces the tool to not look for the EK certificates
    on the NV indices.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# NOTES

When the verbose option is specified, additional curl debugging information is
provided by setting the curl mode verbose, see
<https://curl.haxx.se/libcurl/c/CURLOPT_VERBOSE.html> for more information.

# EXAMPLES

## Retrieve EK certificate from TPM manufacturer backend by supplying EK public.
```bash
tpm2_createek -G rsa -u ek.pub -c key.ctx

tpm2_getekcertificate -X -o ECcert.bin -u ek.pub \
https://tpm.manufacturer.com/ekcertserver/
```

## Retrieve EK certificate from Intel backend if certificate not found on NV.
```bash
tpm2_createek -G rsa -u ek.pub -c key.ctx

tpm2_getekcertificate -X -o ECcert.bin -u ek.pub
```

## Retrieve EK certificate from Intel backend for an offline platform.
```bash
tpm2_getekcertificate -X -x -o ECcert.bin -u ek.pub
```

## Retrieve EK certificate from TPM NV indices only, fail otherwise.
```bash
tpm2_getekcertificate -o ECcert.bin
```

## Retrieve multiple EK certificates from TPM NV indices only, fail otherwise.
```bash
tpm2_getekcertificate -o RSA_EK_cert.bin -o ECC_EK_cert.bin
```

[returns](common/returns.md)

[footer](common/footer.md)
