% tpm2_certifyX509certutil(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_certifyX509certutil**(1) - Generate partial X509 certificate.

# SYNOPSIS

**tpm2_certifyX509certutil** [*OPTIONS*]

# DESCRIPTION

**tpm2_certifyX509certutil**(1) - Generates a partial certificate
that is suitable as the third input parameter for TPM2_certifyX509 command.
The certificate data is written into a file in DER format and can be examined
using openssl asn1parse tool as follows:

```bash
openssl asn1parse -in partial_cert.der -inform DER
```

# OPTIONS
These are the available options:

  * **-o**, **\--outcert**=_STRING_:
    The output file where the certificate will be written to.
	The default is partial_cert.der
    Optional parameter.

  * **-d**, **\--days**=_NUMBER_:
    The number of days the certificate will be valid starting from today.
	The default is 3560 (10 years)
	Optional parameter.

  * **-i**, **\--issuer**=_STRING_:
    The ISSUER entry for the cert in the following format:
	--issuer="C=US;O=org;OU=Org unit;CN=cname"
	Supported fields are:
	* C - "Country", max size = 2
	* O - "Org", max size = 8
	* OU - "Org Unit", max size = 8
	* CN - "Common Name", max size = 8
	The files need to be separated with semicolon.
	At list one supported field is required for the option to be valid.
	Optional parameter.

  * **-s**, **\--subject**=_STRING_:
    The  SUBJECT for the cert in the following format:
	--subject="C=US;O=org;OU=Org unit;CN=cname"
	Supported fields are:
	* C - "Country", max size = 2
	* O - "Org", max size = 8
	* OU - "Org Unit", max size = 8
	* CN - "Common Name", max size = 8
	The files need to be separated with semicolon.
	At list one supported field is required for the option to be valid.
	Optional parameter.

  * **ARGUMENT**
    No arguments required.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

# EXAMPLES

```bash
tpm2 certifyX509certutil -o partial_cert.der -d 356
```

[returns](common/returns.md)

[footer](common/footer.md)
